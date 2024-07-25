
#ifndef __NETPIPE_COMPAT_H__
#define __NETPIPE_COMPAT_H__


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsvc.h>
#include "vio_sockets.h"
#else
#include <stdarg.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <sys/wait.h>
#include <poll.h>
#include <linux/vm_sockets.h>
#endif


#ifndef _WIN32
#define closesocket(a)			close(a)
#define ioctlsocket             ioctl
#define SD_RECEIVE				SHUT_RD
#define SD_SEND					SHUT_WR
#define SD_BOTH					SHUT_RDWR
#define SOCKET_ERROR			-1
#define INVALID_SOCKET			-1
#define SOCKET					int
typedef int ADDRESS_FAMILY;
#else
typedef int ssize_t;
#define poll(a, b, c)			WSAPoll(a, b, c)
#define sleep(t)				Sleep((t) * 1000)

struct sockaddr_un {
    ADDRESS_FAMILY sun_family;               /* AF_UNIX */
    char        sun_path[108];            /* Pathname */
};

#define SUN_LEN(a) (FIELD_OFFSET(struct sockaddr_un, sun_path) + strlen(a->sun_path))

#endif




#endif