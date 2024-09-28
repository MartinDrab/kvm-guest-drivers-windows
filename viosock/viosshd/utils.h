
#ifndef __UTILS_H__
#define __UTILS_H__

#include "compat-header.h"


#define ADDR_PREFIX_IPV4		"ip4://"
#define ADDR_PREFIX_IPV6		"ip6://"
#define ADDR_PREFIX_UNIX		"unix://"
#define ADDR_PREFIX_VSOCK		"vsock://"

int SocketError();
void ProcessAddress(const char* Address, const char **RealAddress, ADDRESS_FAMILY *Family);



#endif
