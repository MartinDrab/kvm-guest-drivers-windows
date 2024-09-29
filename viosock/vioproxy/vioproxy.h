
#ifndef __VIOSSHD_H__
#define __VIOSSHD_H__


#include "compat-header.h"

typedef enum _EOptionType {
	otUnknown,
	otSourceHost,
	otTargetHost,
	otLogError,
	otLogWarning,
	otLogInfo,
	otLogPacket,
	otHelp,
	otVersion,
	otLogPacketData,
	otLogFile,
} EOptionType, *PEOptionType;

typedef struct _COMMAND_LINE_OPTION {
	EOptionType Type;
	int Specified;
	int ArgumentCount;
	size_t NameCount;
	char *Names[2];
	char *ArgumentType;
	char *Description;
} COMMAND_LINE_OPTION, *PCOMMAND_LINE_OPTION;

#ifdef _WIN32
extern volatile int _terminated;
extern COMMAND_LINE_OPTION _cmdOptions[21];
#endif

int ViosockProxyPraseCommandLine(int argc, char **argv);
int ViosockProxyMain(void);



#endif
