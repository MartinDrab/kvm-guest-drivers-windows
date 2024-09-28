
#include "compat-header.h"
#include "utils.h"


int SocketError()
{
	int ret = 0;
#ifdef _WIN32
	ret = WSAGetLastError();
	errno = ret;
	switch (ret) {
		case WSAEWOULDBLOCK:
			errno = EWOULDBLOCK;
			break;
	}
#endif
	ret = errno;

	return ret;
}


void ProcessAddress(const char* Address, const char** RealAddress, ADDRESS_FAMILY* Family)
{
	const char* prefixes[] = {
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

#ifdef _WIN32
	families[3] = ViosockGetAF();
#else
	families[3] = AF_VSOCK;
#endif
	* Family = AF_UNSPEC;
	*RealAddress = Address;
	for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
		const char* p = prefixes[i];
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
