
#include "compat-header.h"
#include "logging.h"
#include "win-utils.h"


DWORD WinAdjustPrivileges(HANDLE hProcess)
{
	DWORD ret = 0;
	HANDLE hToken = 0;
	const wchar_t* privs[] = {
		SE_BACKUP_NAME,
		SE_RESTORE_NAME,
		SE_TCB_NAME,
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_IMPERSONATE_NAME,
	};

	if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		ret = GetLastError();
		LogError("OpenProcessToken: %u", ret);
		goto Exit;
	}

	for (size_t i = 0; i < sizeof(privs) / sizeof(privs[0]); ++i) {
		TOKEN_PRIVILEGES p;

		memset(&p, 0, sizeof(p));
		p.PrivilegeCount = 1;
		p.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!LookupPrivilegeValueW(NULL, privs[i], &p.Privileges[0].Luid)) {
			ret = GetLastError();
			LogWarning("LookupPrivilegeValueW(%ls): %u", privs[i], ret);
			continue;
		}

		if (!AdjustTokenPrivileges(hToken, FALSE, &p, sizeof(p), NULL, NULL)) {
			ret = GetLastError();
			LogWarning("AdjustTokenPrivileges(%ls): %u", privs[i], ret);
			continue;
		}
	}

	CloseHandle(hToken);
Exit:
	return ret;
}


BOOL WinCreateAsynchronousPipe(PPIPE_ENDS Pipe)
{
	DWORD dwError;
	HANDLE ReadPipeHandle = NULL;
	HANDLE WritePipeHandle = NULL;
	wchar_t PipeNameBuffer[MAX_PATH];
	static volatile LONG PipeSerialNumber;

	swprintf(PipeNameBuffer, sizeof(PipeNameBuffer) / sizeof(PipeNameBuffer[0]), L"\\\\.\\Pipe\\RemoteExeAnon.%x.%x", GetCurrentProcessId(), InterlockedIncrement(&PipeSerialNumber));
	ReadPipeHandle = CreateNamedPipeW(PipeNameBuffer, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 16384, 16384, 120 * 1000, NULL);
	if (ReadPipeHandle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	WritePipeHandle = CreateFileW(PipeNameBuffer, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (WritePipeHandle == INVALID_HANDLE_VALUE) {
		dwError = GetLastError();
		CloseHandle(ReadPipeHandle);
		SetLastError(dwError);
		return FALSE;
	}

	Pipe->ReadEnd = ReadPipeHandle;
	Pipe->WriteEnd = WritePipeHandle;

	return TRUE;
}


void WinCloseAsynchronousPipe(PPIPE_ENDS Pipe)
{
	if (Pipe->ReadEnd != NULL) {
		CloseHandle(Pipe->ReadEnd);
		Pipe->ReadEnd = NULL;
	}

	if (Pipe->WriteEnd != NULL) {
		CloseHandle(Pipe->WriteEnd);
		Pipe->WriteEnd = NULL;
	}

	return;
}


BOOL WinCreateStdPipes(PPIPE_ENDS StdIn, PPIPE_ENDS StdOut, PPIPE_ENDS StdErr)
{
	BOOL ret = FALSE;
	DWORD err = ERROR_GEN_FAILURE;

	ret = WinCreateAsynchronousPipe(StdIn);
	if (!ret) {
		err = GetLastError();
		goto Exit;
	}

	ret = WinCreateAsynchronousPipe(StdOut);
	if (!ret) {
		err = GetLastError();
		goto CloseIn;
	}

	ret = WinCreateAsynchronousPipe(StdErr);
	if (!ret) {
		err = GetLastError();
		goto CloseOut;
	}

	ret = SetHandleInformation(StdIn->ReadEnd, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	if (!ret) {
		err = GetLastError();
		goto CloseErr;
	}

	ret = SetHandleInformation(StdOut->WriteEnd, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	if (!ret) {
		err = GetLastError();
		goto CloseErr;
	}

	ret = SetHandleInformation(StdErr->WriteEnd, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	if (!ret) {
		err = GetLastError();
		goto CloseErr;
	}

	goto Exit;
CloseErr:
	WinCloseAsynchronousPipe(StdErr);
CloseOut:
	WinCloseAsynchronousPipe(StdOut);
CloseIn:
	WinCloseAsynchronousPipe(StdIn);
Exit:
	if (!ret)
		SetLastError(err);

	return ret;
}


void WinCloseDistantEnds(PPIPE_ENDS StdIn, PPIPE_ENDS StdOut, PPIPE_ENDS StdErr)
{
	if (StdIn->ReadEnd != NULL) {
		CloseHandle(StdIn->ReadEnd);
		StdIn->ReadEnd = NULL;
	}

	if (StdOut->WriteEnd != NULL) {
		CloseHandle(StdOut->WriteEnd);
		StdOut->WriteEnd = NULL;
	}

	if (StdErr->WriteEnd != NULL) {
		CloseHandle(StdErr->WriteEnd);
		StdErr->WriteEnd = NULL;
	}

	return;
}
