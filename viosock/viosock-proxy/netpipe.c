
#include "compat-header.h"
#include "logging.h"
#include "netpipe.h"


typedef struct _CHANNEL_DATA {
	SOCKET SourceSocket;
	SOCKET DestSocket;
	char *SourceAddress;
	char *DestAddress;
	struct timeval Timeout;
} CHANNEL_DATA, *PCHANNEL_DATA;

typedef enum _ECommEndType {
	cetConnect,
	cetAccept,
} ECommEndType, *PECommEndType;

typedef struct _CHANNEL_END {
	ECommEndType Type;
	char *Address;
	char *AcceptAddress;
	int AddressFamily;
	SOCKET EndSocket;
	SOCKET ListenSocket;
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
static volatile int _terminated = 0;



static int _StreamData(SOCKET Source, SOCKET Dest, uint32_t Flags)
{
	int ret = 0;
	ssize_t len = 0;
	char dataBuffer[4096];

	len = recv(Source, dataBuffer, sizeof(dataBuffer), 0);
	if (len > 0) {
		ret = 1;
		LogPacket("<<< %zu bytes received", len);
		while (len > 0) {
			ssize_t tmp = 0;

			tmp = send(Dest, dataBuffer, len, 0);
			if (tmp == -1) {
				ret = -1;
				break;
			}
			
			if (tmp >= 0)
				LogPacket(">>> %zu bytes sent", tmp);
		
			len -= tmp;
		}
	} else if (len == -1)
		ret = -1;

	return ret;
}


static void _ProcessChannel(PCHANNEL_DATA Data)
{
	int ret = 0;
	fd_set fs;
	struct timeval tv;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	FD_ZERO(&fs);
	FD_SET(Data->SourceSocket, &fs);
	LogInfo("Starting to process the connection (%s --> %s)", Data->SourceAddress, Data->DestAddress);
	do {
		ret = select(0, &fs, NULL, NULL, &tv);
		if (ret > 0) {
			ret = _StreamData(Data->SourceSocket, Data->DestSocket, 0);
			switch (ret) {
				case 0:
					LogInfo("Connection closed");
					ret = -1;
					break;
				case -1:
					LogError("Connection aborted");
					break;
				default:
					ret = 0;
					break;
			}
		} else if (ret == SOCKET_ERROR) { 
			if (errno == EINTR)
				ret = 0;
#ifdef _WIN32
			if (WSAGetLastError() == WSAETIMEDOUT)
				ret = 0;
#endif
		}
	} while (!_terminated && ret >= 0);

	shutdown(Data->SourceSocket, SD_BOTH);
	closesocket(Data->SourceSocket);
	if (Data->SourceAddress != NULL)
		free(Data->SourceAddress);

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
	int af = AF_UNSPEC;
	SOCKET sock = INVALID_SOCKET;
	struct addrinfo hints;
	struct addrinfo *addrs = NULL;
	struct sockaddr_storage acceptAddr;
	int acceptAddrLen = sizeof(acceptAddr);
	struct sockaddr *genAddr = NULL;
	socklen_t genAddrLen = 0;
	struct sockaddr_un *unixAddress = NULL;
	struct sockaddr_vm *vm = NULL;

	switch (End->AddressFamily) {
		case AF_UNSPEC:
		case AF_INET:
		case AF_INET6:
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = End->AddressFamily;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = 0;
			ret = getaddrinfo(End->Address, NULL, &hints, &addrs);
			if (ret == 0) {
				af = addrs->ai_family;
				if (af == AF_UNSPEC)
					af = End->AddressFamily;

				genAddr = addrs->ai_addr;
				genAddrLen = (socklen_t)addrs->ai_addrlen;
			} else LogError("getaddrinfo: %i", ret);
			break;
		case AF_UNIX:
			af = AF_UNIX;
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

	if (ret == 0) {
		LogInfo("Creating a socket");
		sock = socket(af, SOCK_STREAM, 0);
		if (sock != INVALID_SOCKET) {
			switch (End->Type) {
				case cetAccept:
					if (End->ListenSocket == INVALID_SOCKET) {
						LogInfo("Binding the socket");
						ret = bind(sock, genAddr, genAddrLen);
						if (ret == 0) {
							LogInfo("Listening");
							ret = listen(sock, SOMAXCONN);
							if (ret == -1)
								LogError("Error %u", errno);
						} else LogError("Error %u", errno);
					}

					if (ret == 0) {
						fd_set fs;
						struct timeval tv;
						SOCKET listenSocket = INVALID_SOCKET;

						listenSocket = (End->ListenSocket != INVALID_SOCKET ? End->ListenSocket : sock);
						FD_ZERO(&fs);
						FD_SET(listenSocket, &fs);
						tv.tv_sec = 1;
						tv.tv_usec = 0;
						LogInfo("Selecting...");
						do {
							ret = select(0, &fs, NULL, NULL, &tv);
							if (ret > 0) {
								LogInfo("Accepting...");
								End->EndSocket = accept(listenSocket, (struct sockaddr *)&acceptAddr, &acceptAddrLen);
								if (End->EndSocket != INVALID_SOCKET) {
									End->AcceptAddress = sockaddrstr((struct sockaddr *)&acceptAddr);
									if (End->AcceptAddress != NULL) {
										ret = 0;
										LogInfo("Accepted a connection from %s", End->AcceptAddress);
										End->ListenSocket = sock;
										sock = INVALID_SOCKET;
									} else ret = ENOMEM;

									if (End->AcceptAddress == NULL) {
										LogError("Out of memory");
										closesocket(End->EndSocket);
										End->EndSocket = INVALID_SOCKET;
									}
								} else ret = errno;

								if (ret == 0)
									break;
							} else if (ret == SOCKET_ERROR) {
								if (errno == EINTR)
									ret = 0;

#ifdef _WIN32
								if (WSAGetLastError() == WSAETIMEDOUT)
									ret = 0;
#endif
							}
						} while (!_terminated && ret == 0);

						if (End->EndSocket == INVALID_SOCKET)
							ret = -1;
					}
					break;
				case cetConnect:
					End->AcceptAddress = sockaddrstr(genAddr);
					if (End->AcceptAddress != NULL) {
						LogInfo("Connesting to %s (%s)", End->Address, End->AcceptAddress);
						if (genAddr != NULL) {
							ret = connect(sock, genAddr, genAddrLen);
							if (ret == 0) {
								End->EndSocket = sock;
								sock = INVALID_SOCKET;
							}
						} else ret = EINVAL;
					} else {
						ret = ENOMEM;
						LogError("Out of memory");
					}
					break;
			}

			if (sock != INVALID_SOCKET)
				closesocket(sock);
		} else ret = errno;

		if (unixAddress != NULL)
			free(unixAddress);
		
		if (addrs != NULL)
			freeaddrinfo(addrs);

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


#define ADDR_PREFIX_IPV4		"ip4://"
#define ADDR_PREFIX_IPV6		"ip6://"
#define ADDR_PREFIX_UNIX		"unix://"
#define ADDR_PREFIX_VSOCK		"vsock://"


static void _ProcessAddress(const char *Address, const char **RealAddress, ADDRESS_FAMILY *Family)
{
	const char *prefixes[] = {
		ADDR_PREFIX_IPV4,
		ADDR_PREFIX_IPV6,
		ADDR_PREFIX_UNIX,
		ADDR_PREFIX_VSOCK,
	};
	ADDRESS_FAMILY families[] = {
		AF_INET,
		AF_INET6,
		AF_UNIX,
		0,
	};
	const size_t len = strlen(Address);

	families[3] = ViosockGetAF();
	*Family = AF_UNSPEC;
	*RealAddress = Address;
	for (size_t i = 0; i < sizeof(prefixes)/sizeof(prefixes[0]); ++i) {
		const char *p = prefixes[i];
		const size_t pLen = strlen(p);
		const ADDRESS_FAMILY f = families[i];
		
		if (pLen <= len &&
			memcmp(Address, p, pLen) == 0) {
			*Family = f;
			*RealAddress = Address + pLen;
			break;
		}
	}

	return;
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
	fprintf(stderr, "Usage: netpipe <mode> [options]\n");
	fprintf(stderr, "Supported modes:\n");
	fprintf(stderr, "  aa - accept connection from both source and destination\n");
	fprintf(stderr, "  ac - accept connection from the source, make connection to the target\n");
	fprintf(stderr, "  ca - make connection to the source, accept connection from the target\n");
	fprintf(stderr, "  cc - connect to both source and target\n");
	fprintf(stderr, "The connection to the target is established only after the source connection\n");
	fprintf(stderr, "Options:\n");
	for (const COMMAND_LINE_OPTION *c = _cmdOptions; c->Type != otUnknown; c++) {
		fprintf(stderr, "  %s", c->Names[0]);
		for (int i = 1 ; i < c->NameCount; i++)
			fprintf(stderr, ", %s", c->Names[i]);

		if (c->ArgumentType != NULL)
			fprintf(stderr, " <%s>", c->ArgumentType);

		if (c->Description)
			fprintf(stderr, " - %s", c->Description);

		fputc('\n', stderr);
	}

	return;
}



int main(int argc, char *argv[])
{
	int ret = 0;
	char *mode = NULL;

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
	} else {
		fprintf(stderr, "Unknown operating mode \"%s\"\n", mode);
		return -2;
	}

	char **arg = argv + 2;
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
				_ProcessAddress(*arg, &_sourceAddress, &_sourceAF);
				break;
			case otTargetHost:
				_targetAddress = *arg;
				_ProcessAddress(*arg, &_targetAddress, &_destAF);
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
			fprintf(stderr, "Missing argument for command-line option \"%s\"\n", *(arg - 1));
			return ret;
			break;
		case -4:
			fprintf(stderr, "Unknown command-line option \"%s\"\n", *(arg - 1));
			return ret;
			break;
		default:
			break;
	}

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
	source.ListenSocket = INVALID_SOCKET;
	memset(&dest, 0, sizeof(dest));
	dest.ListenSocket = INVALID_SOCKET;
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
				PCHANNEL_DATA d = NULL;

				d = (PCHANNEL_DATA)malloc(sizeof(CHANNEL_DATA)*2);
				if (d != NULL) {
					d[0].Timeout.tv_sec = 5;
					d[0].Timeout.tv_usec = 0;
					d[0].SourceAddress = source.AcceptAddress;
					d[0].DestAddress = dest.AcceptAddress;
					d[0].SourceSocket = source.EndSocket;
					d[0].DestSocket = dest.EndSocket;

					d[1].Timeout.tv_sec = 5;
					d[1].Timeout.tv_usec = 0;
					d[1].SourceAddress = dest.AcceptAddress;
					d[1].DestAddress = source.AcceptAddress;
					d[1].SourceSocket = dest.EndSocket;
					d[1].DestSocket = source.EndSocket;
#ifdef _WIN32
					DWORD threadId = 0;
					HANDLE ths[2];;

					memset(ths, 0, sizeof(ths));
					for (size_t i = 0; i < 2; ++i) {
						ths[i] = CreateThread(NULL, 0, _ChannelThreadWrapper, d + i, 0, &threadId);
						if (ths[i] == NULL) {
							ret = GetLastError();
							for (size_t j = 0; j < i; ++i) {
								shutdown(d[j].SourceSocket, SD_BOTH);
								WaitForSingleObject(ths[j], INFINITE);
								CloseHandle(ths[j]);
							}
							
							shutdown(d[i].SourceSocket, SD_BOTH);
							closesocket(d[i].SourceSocket);
							free(d);
							break;
						}
					}

					if (ret == 0) {
						for (size_t i = 0; i < 2; ++i)
							CloseHandle(ths[i]);
					}
#else
					for (size_t i = 0; i < 2; ++i) {
						ret = fork();
						if (ret > 0) {
							ret = 0;
						} else if (ret == 0) {
							_ProcessChannel(d + i);
							return 0;
						}
					}

					close(d->DestSocket);
					close(d->SourceSocket);
					free(d);
#endif
				} else ret = ENOMEM;

				if (dest.ListenSocket != INVALID_SOCKET) {
					closesocket(dest.ListenSocket);
					dest.ListenSocket = INVALID_SOCKET;
				}

				if (ret != 0)
					closesocket(dest.EndSocket);
			} else LogError("Failed to prepare the target channel: %u", ret);

			if (ret != 0)
				closesocket(source.EndSocket);
		} else LogError("Failed to prepare the source channel: %u", ret);

		sleep(_timeout);
	}


#ifdef _WIN32
	WSACleanup();
#endif

	return ret;
}
