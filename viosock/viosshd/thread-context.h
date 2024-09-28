
#ifndef __THREAD_CONTEXT_H__
#define __THREAD_CONTEXT_H__

#include "compat-header.h"


typedef struct _CHANNEL_DATA {
	SOCKET SourceSocket;
	SOCKET DestSocket;
	char* SourceAddress;
	char* DestAddress;
	struct timeval Timeout;
#ifdef _WIN32
	OVERLAPPED SourceOverlapped;
	void* SourceBuffer;
	volatile LONG Shutdown;
	volatile LONG* pShutdown;
#endif
	int DontCloseDestSocket : 1;
	int SourcePipe : 1;
	int DestPipe : 1;
} CHANNEL_DATA, * PCHANNEL_DATA;


PCHANNEL_DATA ThreadContextAlloc(const char* SourceAddress, const char* DestAddress, SOCKET SourceSocket, SOCKET DestSocket);
void ThreadContextFree(PCHANNEL_DATA Ctx);



#endif
