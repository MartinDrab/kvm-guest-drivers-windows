
#include "compat-header.h"
#include "logging.h"
#include "win-utils.h"
#include "vioproxy.h"
#include "stderr-thread.h"



typedef struct _STDERR_THREAD_CONTEXT {
	HANDLE hProcess;
	HANDLE hEvent;
	HANDLE hPipe;
} STDERR_THREAD_CONTEXT, * PSTDERR_THREAD_CONTEXT;


static DWORD WINAPI _StdErrThreadRoutine(PVOID Context)
{
	OVERLAPPED o;
	DWORD ret = 0;
	char buffer[2049];
	BOOLEAN isPending = FALSE;
	DWORD bytesTransferred = 0;
	PSTDERR_THREAD_CONTEXT ctx = (PSTDERR_THREAD_CONTEXT)Context;

	while (!_terminated && ret == 0) {
		bytesTransferred = 0;
		isPending = FALSE;
		memset(&o, 0, sizeof(o));
		o.hEvent = ctx->hEvent;
		memset(buffer, 0, sizeof(buffer));
		if (!ReadFile(ctx->hPipe, buffer, sizeof(buffer) - 1, &bytesTransferred, &o)) {
			ret = GetLastError();
			if (ret == ERROR_IO_PENDING) {
				isPending = TRUE;
				ret = 0;
			}

			if (ret == ERROR_BROKEN_PIPE) {
				ret = 0;
				break;
			}
		}

		if (ret != 0) {
			LogError("STDERR: ReadFile: %u", ret);
			break;
		}

		ret = WaitForSingleObject(o.hEvent, INFINITE);
		switch (ret) {
			case WAIT_OBJECT_0: {
				if (isPending && !GetOverlappedResult(ctx->hPipe, &o, &bytesTransferred, TRUE)) {
					ret = GetLastError();
					if (ret != ERROR_BROKEN_PIPE)
						LogError("STDERR: GetOverlappedResult: %u", ret);

					break;
				}

				LogInfo("STDERR (%u): %s", bytesTransferred, buffer);
			} break;
			default:
				ret = GetLastError();
				LogError("STDERR: WaitForSingleObject: %u", ret);
				break;
		}
	}

	if (ret == ERROR_BROKEN_PIPE)
		ret = 0;

	if (ret != 0) {
		LogError("STDERR: Terminating the process with error %u", ret);
		TerminateProcess(ctx->hProcess, ret);
	}

	CloseHandle(ctx->hProcess);
	CloseHandle(ctx->hEvent);
	CloseHandle(ctx->hPipe);
	free(ctx);

	return ret;
}


DWORD StdErrThreadCreate(HANDLE hProcess, HANDLE hPipe)
{
	DWORD ret = 0;
	DWORD tid = 0;
	HANDLE hThread = NULL;
	PSTDERR_THREAD_CONTEXT ctx = NULL;

	ctx = malloc(sizeof(STDERR_THREAD_CONTEXT));
	if (ctx == NULL) {
		ret = ERROR_NOT_ENOUGH_MEMORY;
		goto Exit;
	}

	memset(ctx, 0, sizeof(STDERR_THREAD_CONTEXT));
	ctx->hPipe = hPipe;
	ctx->hProcess = hProcess;
	ctx->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (ctx->hEvent == NULL) {
		ret = GetLastError();
		goto FreeCtx;
	}

	hThread = CreateThread(NULL, 0, _StdErrThreadRoutine, ctx, 0, &tid);
	if (hThread == NULL) {
		ret = GetLastError();
		goto CloseEvent;
	}

	CloseHandle(hThread);
	ctx = NULL;
CloseEvent:
	if (ctx != NULL)
		CloseHandle(ctx->hEvent);
FreeCtx:
	if (ctx != NULL)
		free(ctx);
Exit:
	return ret;
}
