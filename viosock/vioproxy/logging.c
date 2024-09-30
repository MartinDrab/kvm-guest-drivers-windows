
#define _CRT_SECURE_NO_WARNINGS
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "logging.h"



uint32_t _loggingFlags = (LOG_FLAG_ERROR | LOG_FLAG_WARNING);
static FILE *_logStream = NULL;
static int _debugger = 0;



void LogMsg(uint32_t Level, const char *Format, ...)
{
	va_list vs;
	char msg[4096];

	if (_loggingFlags & Level) {
		if (_logStream == NULL)
			_logStream = stderr;

		memset(msg, 0, sizeof(msg));
		va_start(vs, Format);
		vsnprintf(msg, sizeof(msg), Format, vs);
#ifdef _WIN32
		if (!_debugger) {
#endif
			fputs(msg, _logStream);
			fflush(_logStream);
#ifdef _WIN32
		} else OutputDebugStringA(msg);
#endif
		
		va_end(vs);
	}

	return;
}


int LogSetFile(const char *FileName)
{
	int ret = 0;

	_logStream = fopen(FileName, "wb");
	if (_logStream == NULL)
		ret = errno;

	if (ret == 0)
		_debugger = 0;

	return ret;
}


void LogSetDebugger(int Enable)
{
	_debugger = Enable;

	return;
}
