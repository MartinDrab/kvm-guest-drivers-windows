
#include "compat-header.h"
#include "logging.h"
#include "utils.h"
#include "thread-context.h"
#ifdef _WIN32
#include "win-utils.h"
#include "stderr-thread.h"
#endif
#include "vioproxy.h"


typedef enum _ECommEndType {
	cetConnect,
	cetAccept,
	cetProcess,
} ECommEndType, *PECommEndType;

#define MAX_LISTEN_COUNT					32

typedef struct _CHANNEL_END {
	ECommEndType Type;
	char *Address;
	char *AcceptAddress;
	ADDRESS_FAMILY AddressFamily;
	SOCKET EndSocket;
	size_t ListenCount;
	SOCKET ListenSockets[MAX_LISTEN_COUNT];
	char *ListenAddresses[MAX_LISTEN_COUNT];
#ifdef _WIN32
	WSAEVENT ListenEvents[MAX_LISTEN_COUNT];
	HANDLE hProcess;
	PIPE_ENDS StdIn;
	PIPE_ENDS StdOut;
	PIPE_ENDS StdErr;
#endif
} CHANNEL_END, *PCHANNEL_END;


static char *_sourceAddress = NULL;
static char *_targetAddress = NULL;
static ADDRESS_FAMILY _sourceAF = AF_UNSPEC;
static ADDRESS_FAMILY _destAF = AF_UNSPEC;
static ECommEndType _sourceMode = cetAccept;
static ECommEndType _targetMode = cetConnect;
static uint32_t _timeout = 1;
static int _help = 0;
static int _version = 0;
static char *_logFile = NULL;
volatile int _terminated = 0;


static int _StreamData(PCHANNEL_DATA Data, int ReadPending, uint32_t BytesRead)
{
	int ret = 0;
	ssize_t len = 0;
	char dataBuffer[4096];

	if (Data->SourcePipe) {
#ifdef _WIN32
		if (!ReadPending || GetOverlappedResult((HANDLE)Data->SourceSocket, &Data->SourceOverlapped, &BytesRead, TRUE)) {
			len = BytesRead;
			memcpy(dataBuffer, Data->SourceBuffer, len);
		} else {
			len = 0;
			if (SocketError() != ERROR_BROKEN_PIPE) {
				len = -1;
				LogError("GetOverlappedResult: %u", GetLastError());
			}
		}
#endif
	} else len = recv(Data->SourceSocket, dataBuffer, sizeof(dataBuffer), 0);
	
	if (len > 0) {
		ret = len;
		LogPacket("<<< %i bytes received", len);
		while (len > 0) {
			ssize_t tmp = 0;

			if (Data->DestPipe) {
#ifdef _WIN32
				DWORD bytesWritten = 0;

				if (WriteFile((HANDLE)Data->DestSocket, dataBuffer, len, &bytesWritten, NULL)) {
					tmp = bytesWritten;
				} else {
					tmp = -1;
					LogError("WriteFile: %u", GetLastError());
				}
#endif
			} else tmp = send(Data->DestSocket, dataBuffer, len, 0);
			
			if (tmp == -1) {
				tmp = SocketError();
				if (tmp == EWOULDBLOCK) {
					LogPacket("--- Destination socket full, sleeping...");
					sleep(1);
					continue;
				}

				ret = -1;
				break;
			}
			
			if (tmp >= 0)
				LogPacket(">>> %i of %i bytes sent", tmp, len);
		
			len -= tmp;
		}
	} else if (len == -1)
		ret = -1;

	return ret;
}


static void _ProcessChannel(PCHANNEL_DATA Data)
{
	int ret = 0;
	int isPending = 0;
	uint32_t bytesRead = 0;
	struct timeval tv;
#ifdef _WIN32
	WSAEVENT readEvent = WSA_INVALID_EVENT;
#else
	fd_set fs;
#endif

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = 1;
	tv.tv_usec = 0;
#ifdef _WIN32
	LogInfo("Creating read event");
	readEvent = WSACreateEvent();
	if (readEvent != WSA_INVALID_EVENT) {
		if (Data->SourcePipe) {
			Data->SourceBuffer = malloc(4096);
			if (Data->SourceBuffer != NULL) {
				memset(Data->SourceBuffer, 0, 4096);
			} else ret = SOCKET_ERROR;
		} else ret = WSAEventSelect(Data->SourceSocket, readEvent, FD_OOB | FD_CLOSE | FD_READ);
		
		if (ret == SOCKET_ERROR) {
			ret = SocketError();
			WSACloseEvent(readEvent);
		}
	} else ret = SocketError();
#endif
	if (ret == 0) {
		LogInfo("Starting to process the connection (%s --> %s)", Data->SourceAddress, Data->DestAddress);
		do {
#ifdef _WIN32
			ret = 0;
			bytesRead = 0;
			isPending = 0;
			if (Data->SourcePipe) {				
				memset(&Data->SourceOverlapped, 0, sizeof(Data->SourceOverlapped));
				Data->SourceOverlapped.hEvent = readEvent;
				if (!ReadFile((HANDLE)Data->SourceSocket, Data->SourceBuffer, 4096, &bytesRead, &Data->SourceOverlapped)) {
					ret = GetLastError();
					if (ret == ERROR_IO_PENDING) {
						isPending = TRUE;
						ret = 0;
					}
				
					if (ret != 0) {
						LogError("ReadFile: %i", ret);
						ret = -1;
					}
				}
			}

			if (ret == 0) {
				ret = WSAWaitForMultipleEvents(1, &readEvent, FALSE, tv.tv_sec*1000, TRUE);
				switch (ret) {
					case WSA_WAIT_EVENT_0: {
						ret = 1;
						if (!Data->SourcePipe) {
							WSANETWORKEVENTS nes;

							memset(&nes, 0, sizeof(nes));
							if (WSAEnumNetworkEvents(Data->SourceSocket, readEvent, &nes) == SOCKET_ERROR) {
								ret = -1;
								LogError("WSAEnumNetworkEvents: %i", SocketError());
							}
						}
					} break;
					case WSA_WAIT_TIMEOUT:
					case WSA_WAIT_IO_COMPLETION:
						ret = 0;
						break;
					default:
						ret = -1;
						break;
				}
			}
#else
			FD_ZERO(&fs);
			FD_SET(Data->SourceSocket, &fs);
			ret = select((int)Data->SourceSocket + 1, &fs, NULL, NULL, &tv);
#endif
			if (ret > 0) {
				ret = _StreamData(Data, isPending, bytesRead);
				switch (ret) {
					case 0:
						LogInfo("Connection closed");
						ret = -1;
						break;
					case -1:
						ret = SocketError();
						if (ret == EWOULDBLOCK)
							ret = 0;

						if (ret != 0) {
							LogError("Connection aborted %i", ret);
							ret = -1;
						}
						break;
					default:
						ret = 0;
						break;
				}
			} else if (ret == SOCKET_ERROR) {
				ret = SocketError();
				if (errno == EINTR)
					ret = 0;

				if (ret == EWOULDBLOCK)
					ret = 0;

				if (ret != 0) {
					LogError("Error %i", ret);
					ret = -1;
				}
			}
		} while (!_terminated && ret >= 0
#ifdef _WIN32
			&& InterlockedCompareExchange(Data->pShutdown, 1, 1) == 0
#endif
			);
	
#ifdef _WIN32
		free(Data->SourceBuffer);
		WSACloseEvent(readEvent);
#endif
	}

	LogInfo("Shutting down the socket");
	if (!Data->SourcePipe)
		shutdown(Data->SourceSocket, SD_BOTH);
#ifdef _WIN32
	InterlockedIncrement(Data->pShutdown);
#else
	if (!Data->DestPipe)
		shutdown(Data->DestSocket, SD_BOTH);
#endif
	ThreadContextFree(Data);

	LogInfo("Exitting");
	return;
}


#ifdef _WIN32

static DWORD WINAPI _ChannelThreadWrapper(PVOID Parameter)
{
	_ProcessChannel((PCHANNEL_DATA)Parameter);

	return 0;
}


#endif



char *sockaddrstr(const struct sockaddr *Addr)
{
	size_t len = 0;
	char *ret = NULL;
	const struct sockaddr_in *in4 = NULL;
	const struct sockaddr_in6 *in6 = NULL;
	const struct sockaddr_un *un = NULL;
	const struct sockaddr_vm *vm = NULL;
	const unsigned char *bytes = NULL;
	const unsigned short *words = NULL;

	len = 128;
	ret = (char *)malloc(len);
	if (ret == NULL)
		return ret;

	memset(ret, 0, len);
	switch (Addr->sa_family) {
		case AF_INET:
			in4 = (struct sockaddr_in *)Addr;
			bytes = (unsigned char *)&in4->sin_addr;
			snprintf(ret, len, "%u.%u.%u.%u:%u", bytes[0], bytes[1], bytes[2], bytes[3], ntohs(in4->sin_port));
			break;
		case AF_INET6:
			in6 = (struct sockaddr_in6 *)Addr;
			words = (unsigned short *)&in6->sin6_addr;
			snprintf(ret, len, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%u", words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7], ntohs(in6->sin6_port));
			break;
		case AF_UNIX:
			un = (struct sockaddr_un*)Addr;
			snprintf(ret, len, "%s", un->sun_path);
			break;
		default:
			vm = (struct sockaddr_vm*)Addr;
			snprintf(ret, len, "%u:%u", vm->svm_cid, vm->svm_port);
			break;
	}

	return ret;
}


static int _PrepareChannelEnd(PCHANNEL_END End)
{
	int ret = 0;
	struct addrinfo hints;
	struct addrinfo *addrs = NULL;
	struct sockaddr *genAddr = NULL;
	socklen_t genAddrLen = 0;
	struct sockaddr_un *unixAddress = NULL;
	struct sockaddr_vm *vm = NULL;

	if (End->Type != cetProcess) {
		switch (End->AddressFamily) {
			case AF_UNSPEC:
			case AF_INET:
			case AF_INET6: {
				char *service = NULL;
			
				memset(&hints, 0, sizeof(hints));
				hints.ai_family = End->AddressFamily;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;
				service = End->Address + strlen(End->Address);
				while (service != End->Address && *service != ':')
					--service;


				if (service != End->Address) {
					*service = '\0';
					++service;
				} else service = NULL;

				ret = getaddrinfo(End->Address, service, &hints, &addrs);
				if (service != NULL) {
					--service;
					*service = ':';
				}

				if (ret != 0)
					LogError("getaddrinfo: %i", ret);
			} break;
			case AF_UNIX:
				unixAddress = (struct sockaddr_un *)malloc(sizeof(struct sockaddr_un));
				if (unixAddress != NULL) {
					memset(unixAddress, 0, sizeof(struct sockaddr_un));
					unixAddress->sun_family = AF_UNIX;
					memcpy(unixAddress->sun_path, End->Address, strlen(End->Address));
					genAddr = (struct sockaddr *)unixAddress;
					genAddrLen = SUN_LEN(unixAddress);
				} else ret = ENOMEM;
				break;
			default: {
				ADDRESS_FAMILY af = AF_UNSPEC;

				af = End->AddressFamily;
				vm = (struct sockaddr_vm *)malloc(sizeof(struct sockaddr_vm));
				if (vm != NULL) {
					char *tmp = NULL;
					memset(vm, 0, sizeof(struct sockaddr_vm));
					vm->svm_family = End->AddressFamily;
					vm->svm_cid = strtoul(End->Address, &tmp, 0);
					if (tmp != NULL && *tmp == ':') {
						vm->svm_port = strtoul(tmp + 1, &tmp, 0);
						genAddr = (struct sockaddr*)vm;
						genAddrLen = sizeof(struct sockaddr_vm);
					} else {
						ret = EINVAL;
						LogError("Invalid AF_VSOCK address format");
					}
				} else ret = ENOMEM;
			} break;
		}
	}

	if (ret == 0) {
		if (genAddrLen > 0) {
			addrs = (struct addrinfo *)malloc(sizeof(struct addrinfo));
			if (addrs != NULL) {
				memset(addrs, 0, sizeof(struct addrinfo));
				addrs->ai_family = End->AddressFamily;
				addrs->ai_addr = genAddr;
				addrs->ai_addrlen = genAddrLen;
			} else ret = ENOMEM;
		}

		if (ret == 0) {
			switch (End->Type) {
				case cetAccept:
					if (End->ListenCount == 0) {
						const struct addrinfo *tmp = NULL;

						tmp = addrs;
						while (ret == 0 && tmp != NULL) {
							int nb = 1;
							const size_t index = End->ListenCount;

							End->ListenAddresses[index] = sockaddrstr(tmp->ai_addr);
							if (End->ListenAddresses[index] == NULL) {
								ret = ENOMEM;
								break;
							}

							LogInfo("Creating a socket #%zu", index);
							End->ListenSockets[index] = socket(tmp->ai_family, SOCK_STREAM, tmp->ai_protocol);
							if (End->ListenSockets[index] == INVALID_SOCKET) {
								ret = SocketError();
								free(End->ListenAddresses[index]);
								LogError("Error %i", ret);
								break;
							}
							
							ret = ioctlsocket(End->ListenSockets[index], FIONBIO, &nb);
							if (ret == SOCKET_ERROR) {
								ret = SocketError();
								closesocket(End->ListenSockets[index]);
								free(End->ListenAddresses[index]);
								LogError("Error %i", ret);
								break;
							}

							LogInfo("Binding to address %s", End->ListenAddresses[index]);
							ret = bind(End->ListenSockets[index], tmp->ai_addr, tmp->ai_addrlen);
							if (ret == INVALID_SOCKET) {
								ret = SocketError();
								closesocket(End->ListenSockets[index]);
								free(End->ListenAddresses[index]);
								tmp = tmp->ai_next;
								LogWarning("Error %i", ret);
								continue;
							}
#ifdef _WIN32
							LogInfo("Creating listen event");
							End->ListenEvents[index] = WSACreateEvent();
							if (End->ListenEvents[index] == WSA_INVALID_EVENT) {
								ret = SocketError();
								closesocket(End->ListenSockets[index]);
								free(End->ListenAddresses[index]);
								LogWarning("Error %i", ret);
								break;
							}

							ret = WSAEventSelect(End->ListenSockets[index], End->ListenEvents[index], FD_CLOSE | FD_ACCEPT);
							if (ret == SOCKET_ERROR) {
								ret = SocketError();
								WSACloseEvent(End->ListenEvents[index]);
								closesocket(End->ListenSockets[index]);
								free(End->ListenAddresses[index]);
								LogWarning("Error %i", ret);
								break;
							}
#endif
							LogInfo("Listening...");
							ret = listen(End->ListenSockets[index], SOMAXCONN);
							if (ret == SOCKET_ERROR) {
								ret = SocketError();
#ifdef _WIN32
								WSACloseEvent(End->ListenEvents[index]);
#endif
								closesocket(End->ListenSockets[index]);
								free(End->ListenAddresses[index]);
								LogError("Error %i", ret);
								tmp = tmp->ai_next;
								continue;
							}

							tmp = tmp->ai_next;
							++End->ListenCount;
						}

						if (ret != 0) {
							for (size_t i = 0; i < End->ListenCount; ++i) {
#ifdef _WIN32
								WSACloseEvent(End->ListenEvents[i]);
#endif
								closesocket(End->ListenSockets[i]);
								free(End->ListenAddresses[i]);
							}

							End->ListenCount = 0;
						} else if (End->ListenCount == 0)
							ret = ENOENT;
					}

					if (ret == 0) {
						struct timeval tv;

						memset(&tv, 0, sizeof(tv));
						tv.tv_sec = 1;
						tv.tv_usec = 0;
						LogInfo("Selecting (%zu events)...", End->ListenCount);
						do {
#ifdef _WIN32
							ret = WSAWaitForMultipleEvents(End->ListenCount, End->ListenEvents, FALSE, tv.tv_sec*1000, TRUE);
							switch (ret) {
								case WSA_WAIT_TIMEOUT:
								case WSA_WAIT_IO_COMPLETION:
									ret = 0;
									break;
								case WSA_WAIT_FAILED:
									ret = -1;
									break;
								default: {
									WSANETWORKEVENTS nes;

									if (ret - WSA_WAIT_EVENT_0 < End->ListenCount) {
										memset(&nes, 0, sizeof(nes));
										if (WSAEnumNetworkEvents(End->ListenSockets[ret], End->ListenEvents[ret], &nes) == 0)
											ret += 1;
										else ret = -1;
									} else ret = -1;
								} break;
							}
#else
							fd_set fs;

							FD_ZERO(&fs);
							for (size_t i = 0; i < End->ListenCount; ++i)
								FD_SET(End->ListenSockets[i], &fs);

							ret = select(End->ListenSockets[End->ListenCount - 1] + 1, &fs, NULL, NULL, &tv);
							if (ret > 0) {
								ret = 0;
								for (size_t i = 0; i < End->ListenCount; ++i) {
									if (FD_ISSET(End->ListenSockets[i], &fs)) {
										ret = i + 1;
										break;
									}
								}
							}
#endif
							if (ret > 0) {
								struct sockaddr_storage acceptAddr;
								int acceptAddrLen = sizeof(acceptAddr);

								ret -= 1;
								LogInfo("Accepting...");
								End->EndSocket = accept(End->ListenSockets[ret], (struct sockaddr *)&acceptAddr, &acceptAddrLen);
								if (End->EndSocket != INVALID_SOCKET) {
									End->AcceptAddress = sockaddrstr((struct sockaddr *)&acceptAddr);
									if (End->AcceptAddress != NULL) {
										int ka = 1;									ret = SocketError();

										ret = 0;
										LogInfo("Accepted a connection from %s", End->AcceptAddress);
										ret = setsockopt(End->EndSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&ka, sizeof(ka));;
										if (ret == SOCKET_ERROR) {
											free(End->AcceptAddress);
											End->AcceptAddress = NULL;
										}
									} else ret = ENOMEM;

									if (End->AcceptAddress == NULL) {
										LogError("Error %i", ret);
										closesocket(End->EndSocket);
										End->EndSocket = INVALID_SOCKET;
									}
								} else ret = SocketError();

								if (ret == 0)
									break;

								if (ret == EAGAIN || ret == EWOULDBLOCK)
									ret = 0;
							} else if (ret == SOCKET_ERROR) {
								ret = SocketError();
								if (ret == EINTR)
									ret = 0;

								if (ret == EWOULDBLOCK)
									ret = 0;
#ifdef _WIN32
								if (ret == WSAETIMEDOUT)
									ret = 0;
#endif
							
								if (ret != 0) {
									LogError("%i", ret);
								}									
							}
						} while (!_terminated && ret == 0);
					}
					break;
				case cetConnect: {
					const struct addrinfo *tmp = NULL;

					tmp = addrs;
					while (tmp != NULL) {
						int nb = 1;
						char *addrstr = NULL;

						addrstr = sockaddrstr(tmp->ai_addr);
						if (addrstr == NULL) {
							ret = ENOMEM;
							break;
						}

						LogInfo("Creating a socket for %s", addrstr);
						End->EndSocket = socket(tmp->ai_family, SOCK_STREAM, tmp->ai_protocol);
						if (End->EndSocket == INVALID_SOCKET) {
							ret = SocketError();
							free(addrstr);
							LogError("Error %i", ret);
							tmp = tmp->ai_next;
							continue;
						}
					
						LogInfo("Connesting to %s (%s)", End->Address, addrstr);
						ret = connect(End->EndSocket, tmp->ai_addr, tmp->ai_addrlen);
						if (ret == SOCKET_ERROR) {
							ret = SocketError();
							closesocket(End->EndSocket);
							End->EndSocket = INVALID_SOCKET;
							free(addrstr);
							LogError("connect: %i", ret);
							tmp = tmp->ai_next;
							continue;
						}

						ret = setsockopt(End->EndSocket, SOL_SOCKET, SO_KEEPALIVE, (char *)&nb, sizeof(nb));;
						if (ret == SOCKET_ERROR) {
							ret = SocketError();
							closesocket(End->EndSocket);
							End->EndSocket = INVALID_SOCKET;
							free(addrstr);
							LogError("setsockopt: %i", ret);
							tmp = tmp->ai_next;
							continue;
						}

						ret = ioctlsocket(End->EndSocket, FIONBIO, &nb);
						if (ret == SOCKET_ERROR) {
							ret = SocketError();
							closesocket(End->EndSocket);
							End->EndSocket = INVALID_SOCKET;
							free(addrstr);
							LogError("ioctlsocket: %i", ret);
							tmp = tmp->ai_next;
							continue;
						}

						End->AcceptAddress = addrstr;
						break;
					}

				} break;
#ifdef _WIN32
				case cetProcess: {
					LogInfo("Creating stdin/stdout pipes...");
					if (WinCreateStdPipes(&End->StdIn, &End->StdOut, &End->StdErr)) {
						End->AcceptAddress = strdup(End->Address);
						if (End->AcceptAddress != NULL) {
							STARTUPINFOA si;
							PROCESS_INFORMATION pi;

							LogInfo("Running %s", End->AcceptAddress);
							memset(&si, 0, sizeof(si));
							si.cb = sizeof(si);
							si.dwFlags = STARTF_USESTDHANDLES;
							si.hStdInput = End->StdIn.ReadEnd;
							si.hStdOutput = End->StdOut.WriteEnd;
							si.hStdError = End->StdErr.WriteEnd;
							memset(&pi, 0, sizeof(pi));
							if (!CreateProcessA(NULL, End->AcceptAddress, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
								ret = GetLastError();

							if (ret == 0) {
								WinCloseDistantEnds(&End->StdIn, &End->StdOut, &End->StdErr);
								WinAdjustPrivileges(pi.hProcess);
								ResumeThread(pi.hThread);
								CloseHandle(pi.hThread);
								ret = StdErrThreadCreate(pi.hProcess, End->StdErr.ReadEnd);
								if (ret == 0)
									End->StdErr.ReadEnd = NULL;

								if (ret != 0) {
									TerminateProcess(pi.hProcess, ret);
									CloseHandle(pi.hProcess);
								}
							}
						} else ret = ENOMEM;

						if (ret != 0) {
							WinCloseAsynchronousPipe(&End->StdErr);
							WinCloseAsynchronousPipe(&End->StdIn);
							WinCloseAsynchronousPipe(&End->StdOut);
						}
					} else ret = SocketError();
				} break;
#endif
			}
		}

		if (unixAddress != NULL)
			free(unixAddress);
		
		if (addrs != NULL) {
			if (genAddr != NULL)
				free(addrs);
			else freeaddrinfo(addrs);
		}

		if (vm != NULL)
			free(vm);
	}

	if (ret != 0) {
		if (End->AcceptAddress != NULL) {
			free(End->AcceptAddress);
			End->AcceptAddress = NULL;
		}

		if (End->EndSocket != INVALID_SOCKET &&
			End->EndSocket) {
			closesocket(End->EndSocket);
			End->EndSocket = INVALID_SOCKET;
		}
	}

	return ret;
}


#define arg_advance(aArgc, aArg)	\
	{ --aArgc; ++aArg;  }

COMMAND_LINE_OPTION _cmdOptions[] = {
	{ otSourceHost,      0, 1, 2, {"-d", "--source-host"},       "string",  "Domain/address of the source end" },
	{ otTargetHost,      0, 1, 2, {"-D", "--target-host"},       "string",  "Domain/address of the target end" },
	{ otLogError,        0, 0, 1, {      "--log-error"},         NULL,      "Log error messages" },
	{ otLogWarning,      0, 0, 1, {      "--log-warning"},       NULL,      "Log warnings" },
	{ otLogInfo,         0, 0, 1, {      "--log-info"},          NULL,      "Log information-level messages" },
	{ otLogPacket,       0, 0, 1, {      "--log-packet"},        NULL,      "Log lengths of sent and received data" },
	{ otLogPacketData,   0, 0, 1, {      "--log-packet-data"},   NULL,      "Log data of the transmitted packets" },
	{ otHelp,            0, 0, 2, {"-h", "--help"},              NULL,      "Show this help" },
	{ otLogFile,         0, 1, 2, {"-l", "--log-file"},          "string",  "Log netpipe output to a given file"},
	{ otVersion,         0, 0, 2, {"-v", "--version"},           NULL,      "Show version information" },
	{ otUnknown,         0, 0, 0},
};


void usage(void)
{
	LogInfo("Usage: netpipe <mode> [options]");
	LogInfo("Supported modes:");
	LogInfo("  aa - accept connection from both source and destination");
	LogInfo("  ac - accept connection from the source, make connection to the target");
	LogInfo("  ca - make connection to the source, accept connection from the target");
	LogInfo("  cc - connect to both source and target");
#ifdef _WIN32
	LogInfo("  ap - run the target process on accepting a connection");
	LogInfo("  cp - connect to the source and run the target process");
#endif
	LogInfo("The connection to the target is established only after the source connection");
	LogInfo("Options:\n");
	for (const COMMAND_LINE_OPTION *c = _cmdOptions; c->Type != otUnknown; c++) {
		LogInfo("  %s", c->Names[0]);
		for (int i = 1 ; i < c->NameCount; i++)
			LogInfo(", %s", c->Names[i]);

		if (c->ArgumentType != NULL)
			LogInfo(" <%s>", c->ArgumentType);

		if (c->Description)
			LogInfo(" - %s", c->Description);
	}

	return;
}


int ViosockProxyPraseCommandLine(int argc, char **argv)
{
	int ret = 0;
	const char *mode = NULL;

	if (argc < 2) {
		usage();
		return -1;
	}

	mode = argv[1];
	if (strcmp(mode, "ac") == 0) {
		_sourceMode = cetAccept;
		_targetMode = cetConnect;
	} else if (strcmp(mode, "cc") == 0) {
		_sourceMode = cetConnect;
		_targetMode = cetConnect;
	} else if (strcmp(mode, "aa") == 0) {
		_sourceMode = cetAccept;
		_targetMode = cetAccept;
	} else if (strcmp(mode, "ca") == 0) {
		_sourceMode = cetConnect;
		_targetMode = cetAccept;
	}
#ifdef _WIN32
	else if (strcmp(mode, "ap") == 0) {
		_sourceMode = cetAccept;
		_targetMode = cetProcess;
	} else if (strcmp(mode, "cp") == 0) {
		_sourceMode = cetConnect;
		_targetMode = cetProcess;
	}
#endif
	else {
		LogError("Unknown operating mode \"%s\"", mode);
		return -2;
	}

	char** arg = argv + 2;
	argc -= 2;
	while (ret == 0 && argc > 0) {
		int found = 0;
		PCOMMAND_LINE_OPTION cmdOption = _cmdOptions;

		for (size_t i = 0; i < sizeof(_cmdOptions) / sizeof(_cmdOptions[0]) - 1; ++i) {
			for (size_t j = 0; j < cmdOption->NameCount; ++j) {
				found = (strcmp(*arg, cmdOption->Names[j]) == 0);
				if (found) {
					++cmdOption->Specified;
					if (argc < cmdOption->ArgumentCount) {
						ret = -1;
						LogError("Not enough arguments for the %s option", *arg);
						break;
					}

					if (cmdOption->Specified > 1)
						LogWarning("The %s has been specified for %uth time, the last specification is used", *arg);;

					arg_advance(argc, arg);
					break;
				}
			}

			if (found)
				break;

			++cmdOption;
		}

		switch (cmdOption->Type) {
			case otUnknown:
				ret = -1;
				LogError("Unknown option %s", *arg);
				break;
			case otSourceHost:
				_sourceAddress = *arg;
				if (_sourceMode != cetProcess)
					ProcessAddress(*arg, &_sourceAddress, &_sourceAF);
				break;
			case otTargetHost:
				_targetAddress = *arg;
				if (_targetMode != cetProcess)
					ProcessAddress(*arg, &_targetAddress, &_destAF);
				break;
			case otLogError:
				_loggingFlags |= LOG_FLAG_ERROR;
				break;
			case otLogWarning:
				_loggingFlags |= LOG_FLAG_WARNING;
				break;
			case otLogInfo:
				_loggingFlags |= LOG_FLAG_INFO;
				break;
			case otLogPacket:
				_loggingFlags |= LOG_FLAG_PACKET;
				break;
			case otLogPacketData:
				_loggingFlags |= LOG_FLAG_PACKET_DATA;
				break;
			case otHelp:
				_help = 1;
				break;
			case otVersion:
				_version = 1;
				break;
			case otLogFile:
				_logFile = *arg;
				break;
		}

		if (ret == 0 && cmdOption->ArgumentCount > 0) {
			for (int i = 0; i < cmdOption->ArgumentCount; ++i)
				arg_advance(argc, arg);
		}
	}

	switch (ret) {
		case -3:
			LogError("Missing argument for command-line option \"%s\"", *(arg - 1));
			return ret;
			break;
		case -4:
			LogError("Unknown command-line option \"%s\"", *(arg - 1));
			return ret;
			break;
		default:
			break;
	}

	return ret;
}



int ViosockProxyMain(void)
{
	int ret = 0;

	if (_help) {
		usage();
		return 0;
	}

	if (_version) {
		fprintf(stderr, "NetPipe v1.0\n");
		return 0;
	}

	if (_logFile != NULL) {
		ret = LogSetFile(_logFile);
		if (ret != 0) {
			fprintf(stderr, "Failed to change log file: %u\n", ret);
			return ret;
		}
	}

	if (_sourceAddress == NULL) {
		fprintf(stderr, "Source host not specified\n");
		return -1;
	}

	if (_targetAddress == NULL) {
		fprintf(stderr, "Target host not specified\n");
		return -1;
	}

#ifdef _WIN32
	WSADATA wsaData;

	ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != NO_ERROR) {
		fprintf(stderr, "WSAStartup: %i\n", ret);
		return ret;
	}

#endif
	CHANNEL_END source;
	CHANNEL_END dest;

	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));
	while (!_terminated) {
		source.Type = _sourceMode;
		source.AddressFamily = _sourceAF;
		source.Address = _sourceAddress;
		source.EndSocket = INVALID_SOCKET;
		ret = _PrepareChannelEnd(&source);		
		if (ret == 0) {
			dest.Type = _targetMode;
			dest.AddressFamily = _destAF;
			dest.Address = _targetAddress;
			dest.EndSocket = INVALID_SOCKET;
			ret = _PrepareChannelEnd(&dest);
			if (ret == 0) {
				PCHANNEL_DATA d[2];

				d[0] = ThreadContextAlloc(source.AcceptAddress, dest.AcceptAddress, source.EndSocket, dest.EndSocket);
				if (d[0] != NULL) {
					d[1] = ThreadContextAlloc(dest.AcceptAddress, source.AcceptAddress, dest.EndSocket, source.EndSocket);
					if (d[1] != NULL) {
						d[0]->DontCloseDestSocket = 1;
						d[1]->DontCloseDestSocket = 1;
#ifdef _WIN32
						if (dest.Type == cetProcess) {
							d[0]->DestSocket = (SOCKET)dest.StdIn.WriteEnd;
							d[0]->DestPipe = 1;
							dest.StdIn.WriteEnd = NULL;
							d[0]->DontCloseDestSocket = 0;
							d[1]->SourceSocket = (SOCKET)dest.StdOut.ReadEnd;
							dest.StdOut.ReadEnd = NULL;
							d[1]->SourcePipe = 1;
						}

						d[0]->pShutdown = &d[0]->Shutdown;
						d[1]->pShutdown = &d[0]->Shutdown;
						DWORD threadId = 0;
						HANDLE ths[2];;

						memset(ths, 0, sizeof(ths));
						for (size_t i = 0; i < sizeof(ths)/sizeof(ths[0]); ++i) {
							ths[i] = CreateThread(NULL, 0, _ChannelThreadWrapper, d[i], 0, &threadId);
							if (ths[i] == NULL) {
								ret = GetLastError();
								if (!d[i]->SourcePipe)
									shutdown(d[i]->SourceSocket, SD_BOTH);
								else CloseHandle((HANDLE)d[i]->SourceSocket);

								for (size_t j = 0; j < i; ++i) {
									WaitForSingleObject(ths[j], INFINITE);
									CloseHandle(ths[j]);
								}
							
								break;
							}

							d[i] = NULL;
						}

						if (ret == 0) {
							for (size_t i = 0; i < sizeof(ths)/sizeof(ths[0]); ++i)
								CloseHandle(ths[i]);
						}
#else
						for (size_t i = 0; i < 2; ++i) {
							ret = fork();
							if (ret > 0) {
								ret = 0;
							} else if (ret == 0) {
								_ProcessChannel(d[i]);
								return 0;
							}
						}
#endif
						if (d[1] != NULL)
							ThreadContextFree(d[1]);
					}

					if (d[0] != NULL)
						ThreadContextFree(d[0]);
					
					source.EndSocket = INVALID_SOCKET;
					dest.EndSocket = INVALID_SOCKET;
				}

				if (dest.EndSocket != INVALID_SOCKET)
					closesocket(dest.EndSocket);
			
				if (dest.AcceptAddress != NULL) {
					free(dest.AcceptAddress);
					dest.AcceptAddress = NULL;
				}

#ifdef _WIN32
				WinCloseAsynchronousPipe(&dest.StdIn);
				WinCloseAsynchronousPipe(&dest.StdOut);
#endif
			} else LogError("Failed to prepare the target channel: %u", ret);

			if (source.EndSocket != INVALID_SOCKET)
				closesocket(source.EndSocket);

			if (source.AcceptAddress != NULL) {
				free(source.AcceptAddress);
				source.AcceptAddress = NULL;
			}
		} else LogError("Failed to prepare the source channel: %u", ret);

		sleep(_timeout);
	}


#ifdef _WIN32
	WSACleanup();
#endif

	return ret;
}
