
#ifndef __VIOWSK_TEST_MESSAGES_H__
#define __VIOWSK_TEST_MESSAGES_H__


#include <ntifs.h>
#include <wsk.h>
#include <bcrypt.h>



#define VIOWSK_TEST_MSG_TAG					(ULONG)'MKSW'

#define VIOWSK_MSG_SIZE						4096

NTSTATUS
VioWskMessageGenerate(
	_In_opt_ BCRYPT_HASH_HANDLE SHA256Handle,
	_Out_ PWSK_BUF WskBuffer,
	_Out_ PVOID* FlatBuffer
);

NTSTATUS
VIoWskMessageVerify(
	_In_ BCRYPT_HASH_HANDLE SHA256Handle,
	_In_ const WSK_BUF* WskBuf,
	_Out_ PBOOLEAN Verified
);

NTSTATUS
VIoWskMessageVerifyBuffer(
	_In_ BCRYPT_HASH_HANDLE SHA256Handle,
	_In_ const void* Buffer,
	_Out_ PBOOLEAN Verified
);

void
VioWskMessageAdvance(
	_Inout_ PWSK_BUF WskBuffer,
	_In_ SIZE_T Length
);

void
VioWskMessageFree(
	_In_ PWSK_BUF WskBuffer,
	_In_opt_ PVOID FlatBuffer
);




#endif
