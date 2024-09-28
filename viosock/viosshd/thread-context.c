
#include "compat-header.h"
#include "logging.h"
#include "thread-context.h"




PCHANNEL_DATA ThreadContextAlloc(const char* SourceAddress, const char* DestAddress, SOCKET SourceSocket, SOCKET DestSocket)
{
	PCHANNEL_DATA ret = NULL;

	ret = malloc(sizeof(CHANNEL_DATA));
	if (ret == NULL) {
		errno = ENOMEM;
		goto Exit;
	}

	memset(ret, 0, sizeof(CHANNEL_DATA));
	ret->Timeout.tv_sec = 5;
	ret->Timeout.tv_usec = 0;
	ret->SourceSocket = SourceSocket;
	ret->DestSocket = DestSocket;
	ret->SourceAddress = strdup(SourceAddress);
	if (ret->SourceAddress == NULL) {
		errno = ENOMEM;
		goto FreeContext;
	}

	ret->DestAddress = strdup(DestAddress);
	if (ret->DestAddress == NULL) {
		errno = ENOMEM;
		goto FreeSourceAddress;
	}

	goto Exit;
FreeSourceAddress:
	free(ret->SourceAddress);
FreeContext:
	free(ret);
	ret = NULL;
Exit:
	return ret;
}


void ThreadContextFree(PCHANNEL_DATA Ctx)
{
	if (!Ctx->SourcePipe)
		closesocket(Ctx->SourceSocket);
#ifdef _WIN32
	else CloseHandle((HANDLE)Ctx->SourceSocket);
#endif

	if (!Ctx->DontCloseDestSocket) {
		if (!Ctx->DestPipe)
			closesocket(Ctx->DestSocket);
#ifdef _WIN32
		else CloseHandle((HANDLE)Ctx->DestSocket);
#endif
	}

	free(Ctx->SourceAddress);
	free(Ctx->DestAddress);
	free(Ctx);

	return;
}
