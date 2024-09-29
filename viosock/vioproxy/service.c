
#include "compat-header.h"
#include "logging.h"
#include "vioproxy.h"



#ifdef _WIN32

static SERVICE_STATUS_HANDLE _statusHandle;
static SERVICE_STATUS _statusRecord;


static DWORD WINAPI _SvcHandlerEx(_In_ DWORD  dwControl, _In_ DWORD  dwEventType, _In_ LPVOID lpEventData, _In_ LPVOID lpContext)
{
	DWORD ret = NO_ERROR;

	switch (dwControl) {
	case SERVICE_CONTROL_STOP:
		_statusRecord.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(_statusHandle, &_statusRecord);
		_terminated = 1;
		Sleep(5000);
		_statusRecord.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(_statusHandle, &_statusRecord);
		break;
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default:
		break;
	}

	return ret;
}


static void WINAPI _ServiceMain(_In_ DWORD  dwArgc, _In_ char** lpszArgv)
{
	memset(&_statusRecord, 0, sizeof(_statusRecord));
	_statusHandle = RegisterServiceCtrlHandlerExA("VirtioSSHD", _SvcHandlerEx, NULL);
	if (_statusHandle != NULL) {
		_statusRecord.dwCurrentState = SERVICE_START_PENDING;
		_statusRecord.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		SetServiceStatus(_statusHandle, &_statusRecord);
		_statusRecord.dwCurrentState = SERVICE_RUNNING;
		_statusRecord.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
		SetServiceStatus(_statusHandle, &_statusRecord);
		if (ViosockProxyMain() != 0) {
			_statusRecord.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(_statusHandle, &_statusRecord);
		}
	} else {
		LogError("RegisterServiceCtrlHandlerExA: %u", GetLastError());
	}

	return;
}


#endif


int __cdecl main(int argc, char** argv)
{
	int ret = 0;

	LogSetDebugger(1);
	ret = ViosockProxyPraseCommandLine(argc, argv);
	if (ret == 0) {
#ifdef _WIN32
		SERVICE_TABLE_ENTRYA svcTable[2];

		memset(svcTable, 0, sizeof(svcTable));
		svcTable[0].lpServiceName = "VirtioSSHD";
		svcTable[0].lpServiceProc = _ServiceMain;
		if (!StartServiceCtrlDispatcherA(svcTable)) {
			ret = GetLastError();
			LogWarning("StartServiceCtrlDispatcherA: %u", ret);
			if (ret == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
				ret = ViosockProxyMain();
		}
#else
		ret = ViosockProxyMain();
#endif
	}

	return ret;
}
