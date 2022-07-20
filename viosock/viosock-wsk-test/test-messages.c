
#include <ntifs.h>
#include <wsk.h>
#include <bcrypt.h>
#include "..\inc\debug-utils.h"
#include "test-messages.h"


static ULONG _randSeed;


NTSTATUS
VioWskMessageGenerate(
	_In_opt_ BCRYPT_HASH_HANDLE SHA256Handle,
	_Out_ PWSK_BUF WskBuffer,
	_Out_ PVOID* FlatBuffer
)
{
	PMDL mdl = NULL;
	PVOID buffer = NULL;
	SIZE_T bufferSize = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("SHA256Handle=0x%p; WskBuffer=0x%p", SHA256Handle, WskBuffer);

	Status = STATUS_SUCCESS;
	bufferSize = 4096;
	buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, VIOWSK_TEST_MSG_TAG);
	if (!buffer) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	if (SHA256Handle) {
		for (SIZE_T i = 0; i < (4096 - 32) / sizeof(ULONG); ++i)
			((PULONG)buffer)[i] = RtlRandomEx(&_randSeed);

		Status = BCryptHashData(SHA256Handle, (PUCHAR)buffer, 4096 - 32, 0);
		if (!NT_SUCCESS(Status))
			goto FreeBuffer;

		Status = BCryptFinishHash(SHA256Handle, (PUCHAR)buffer + 4096 - 32, 32, 0);
		if (!NT_SUCCESS(Status))
			goto FreeBuffer;
	}

	WskBuffer->Length = 4096;
	WskBuffer->Offset = 0;
	mdl = IoAllocateMdl(buffer, 4096 - 32, FALSE, FALSE, NULL);
	if (!mdl) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto FreeBuffer;
	}

	MmBuildMdlForNonPagedPool(mdl);
	WskBuffer->Mdl = mdl;
	mdl = IoAllocateMdl((PUCHAR)buffer + (4096 - 32), 32, FALSE, FALSE, NULL);
	if (!mdl) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto FreeWskBuf;
	}

	MmBuildMdlForNonPagedPool(mdl);
	WskBuffer->Mdl->Next = mdl;
	*FlatBuffer = buffer;
	buffer = NULL;
FreeWskBuf:
	if (!NT_SUCCESS(Status))
		IoFreeMdl(WskBuffer->Mdl);
FreeBuffer:
	if (buffer)
		ExFreePoolWithTag(buffer, VIOWSK_TEST_MSG_TAG);
Exit:
	DEBUG_EXIT_FUNCTION("0x%x, *FlatBuffer=0x%p", Status, *FlatBuffer);
	return Status;
}


NTSTATUS
VIoWskMessageVerify(
	_In_ BCRYPT_HASH_HANDLE SHA256Handle,
	_In_ const WSK_BUF* WskBuf,
	_Out_ PBOOLEAN Verified
)
{
	ULONG offset = 0;
	SIZE_T remainingLength = 0;
	PVOID buffer = NULL;
	unsigned char digest[32];
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("SHA256Handle=0x%p; WskBuffer=0x%p; Verified=0x%p", SHA256Handle, WskBuf, Verified);

	Status = STATUS_SUCCESS;
	buffer = ExAllocatePoolWithTag(NonPagedPool, WskBuf->Length, VIOWSK_TEST_MSG_TAG);
	if (!buffer) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	offset = WskBuf->Offset;
	remainingLength = WskBuf->Length;
	for (PMDL mdl = WskBuf->Mdl; mdl != NULL; mdl = mdl->Next) {
		SIZE_T mdlSize = 0;
		PVOID mdlBuffer = NULL;

		mdlBuffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
		if (!mdlBuffer) {
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		mdlSize = MmGetMdlByteCount(mdl) - offset;
		if (mdlSize > remainingLength)
			mdlSize = remainingLength;

		memcpy((unsigned char*)buffer + (WskBuf->Length - remainingLength), (unsigned char*)mdlBuffer + offset, mdlSize);
		offset = 0;
		remainingLength -= mdlSize;
	}

	if (!NT_SUCCESS(Status))
		goto FreeBuffer;

	Status = BCryptHashData(SHA256Handle, (PUCHAR)buffer, (ULONG)(WskBuf->Length - sizeof(digest)), 0);
	if (!NT_SUCCESS(Status))
		goto FreeBuffer;

	Status = BCryptFinishHash(SHA256Handle, digest, sizeof(digest), 0);
	if (!NT_SUCCESS(Status))
		goto FreeBuffer;

	*Verified = (memcmp((unsigned char*)buffer + WskBuf->Length - sizeof(digest), digest, sizeof(digest)) == 0);
FreeBuffer:
	ExFreePoolWithTag(buffer, VIOWSK_TEST_MSG_TAG);
Exit:
	DEBUG_EXIT_FUNCTION("0x%x, *Verified=%u", Status, *Verified);
	return Status;
}


NTSTATUS
VIoWskMessageVerifyBuffer(
	_In_ BCRYPT_HASH_HANDLE SHA256Handle,
	_In_ const void* Buffer,
	_Out_ PBOOLEAN Verified
)
{
	unsigned char digest[32];
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("SHA256Handle=0x%p; Buffer=0x%p; Verified=0x%p", SHA256Handle, Buffer, Verified);

	Status = BCryptHashData(SHA256Handle, (PUCHAR)Buffer, VIOWSK_MSG_SIZE - sizeof(digest), 0);
	if (!NT_SUCCESS(Status))
		goto Exit;

	Status = BCryptFinishHash(SHA256Handle, digest, sizeof(digest), 0);
	if (!NT_SUCCESS(Status))
		goto Exit;

	*Verified = (memcmp((unsigned char*)Buffer + VIOWSK_MSG_SIZE - sizeof(digest), digest, sizeof(digest)) == 0);

Exit:
	DEBUG_EXIT_FUNCTION("0x%x, *Verified=%u", Status, *Verified);
	return Status;
}


void
VioWskMessageAdvance(
	_Inout_ PWSK_BUF WskBuffer,
	_In_ SIZE_T Length
)
{
	PMDL currentMdl = NULL;
	ULONG advanceAmount = 0;
	DEBUG_ENTER_FUNCTION("WskBuffer=0x%p; Length=%zu", WskBuffer, Length);

	currentMdl = WskBuffer->Mdl;
	while (WskBuffer->Length > 0 && Length > 0) {
		advanceAmount = MmGetMdlByteCount(WskBuffer->Mdl) - WskBuffer->Offset;
		if (advanceAmount > Length)
			advanceAmount = (ULONG)Length;
		
		WskBuffer->Offset += advanceAmount;
		if (WskBuffer->Offset == MmGetMdlByteCount(currentMdl)) {
			WskBuffer->Mdl = WskBuffer->Mdl->Next;
			WskBuffer->Offset = 0;
			IoFreeMdl(currentMdl);
			currentMdl = WskBuffer->Mdl;
		}

		WskBuffer->Length -= advanceAmount;
		Length -= advanceAmount;
	}

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}

void
VioWskMessageFree(
	_In_ PWSK_BUF WskBuffer,
	_In_opt_ PVOID FlatBuffer
)
{
	PMDL mdl = NULL;
	DEBUG_ENTER_FUNCTION("WskBuffer=0x%p; FlatBuffer=0x%p", WskBuffer, FlatBuffer);

	mdl = WskBuffer->Mdl;
	while (mdl != NULL) {
		mdl = mdl->Next;
		IoFreeMdl(WskBuffer->Mdl);
		WskBuffer->Mdl = mdl;
	}

	if (FlatBuffer)
		ExFreePoolWithTag(FlatBuffer, VIOWSK_TEST_MSG_TAG);

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}
