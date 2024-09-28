
#ifndef __WIN_UTILS_H__
#define __WIN_UTILS_H__

#include "compat-header.h"


typedef struct _PIPE_ENDS {
	HANDLE ReadEnd;
	HANDLE WriteEnd;
} PIPE_ENDS, *PPIPE_ENDS;


DWORD WinAdjustPrivileges(HANDLE hProcess);
BOOL WinCreateAsynchronousPipe(PPIPE_ENDS Pipe);
void WinCloseAsynchronousPipe(PPIPE_ENDS Pipe);
BOOL WinCreateStdPipes(PPIPE_ENDS StdIn, PPIPE_ENDS StdOut, PPIPE_ENDS StdErr);
void WinCloseDistantEnds(PPIPE_ENDS StdIn, PPIPE_ENDS StdOut, PPIPE_ENDS StdErr);





#endif
