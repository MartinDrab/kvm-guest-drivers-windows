
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <wsk.h>
#include <bcrypt.h>
#include "..\inc\debug-utils.h"
#include "..\inc\vio_wsk.h"
#include "..\inc\vio_sockets.h"
#include "..\sys\public.h"
#include "test-messages.h"



#define LISTEN_PORT_MIN				1337
#define LISTEN_PORT_MAX				1337
#define SERVER_THREAD_COUNT			((LISTEN_PORT_MAX) - (LISTEN_PORT_MIN) + 1)
#define CLIENT_THREAD_COUNT			1


static volatile LONG _readyThreads;
static volatile LONG _terminate;
static PETHREAD _clientThreads[CLIENT_THREAD_COUNT];
static PETHREAD _serverThreads[SERVER_THREAD_COUNT];
static KEVENT _initEvent;
static PDEVICE_OBJECT _shutdownDeviceObject = NULL;
static WSK_REGISTRATION _vioWskRegistration;
static WSK_PROVIDER_NPI _vioWskProviderNPI;
static WSK_CLIENT_NPI _vioWskClientNPI =  {
	NULL,
	NULL,
};


static
NTSTATUS
_GeneralIrpComplete(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp,
	_In_ PVOID Context
)
{
	DEBUG_ENTER_FUNCTION("DeviceObject=0x%p; Irp=0x%p; Context=0x%p", DeviceObject, Irp, Context);

	KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);

	DEBUG_EXIT_FUNCTION("0x%x", STATUS_MORE_PROCESSING_REQUIRED);
	return STATUS_MORE_PROCESSING_REQUIRED;
}


#define WSK_SYNCHRONOUS_CALL(aIrp, aEvent, aCall, aIosb) do {	\
	IoSetCompletionRoutine((aIrp), _GeneralIrpComplete, (aEvent), TRUE, TRUE, TRUE);	\
	(aIosb)->Status = (aCall);	\
	if ((aIosb)->Status == STATUS_PENDING) {	\
		KeWaitForSingleObject((aEvent), Executive, KernelMode, FALSE, NULL);	\
		(aIosb)->Status = (aIrp)->IoStatus.Status;	\
	}	\
	\
	ASSERT((aIosb)->Status == (aIrp)->IoStatus.Status);	\
	(aIosb)->Information = (aIrp)->IoStatus.Information;	\
	KeResetEvent((aEvent));	\
	IoReuseIrp((aIrp), STATUS_UNSUCCESSFUL);	\
} while (FALSE)	\


#define WSK_ASYNCHRONOUS_CALL(aIrp, aEvent, aCall, aIosb) do {	\
	KIRQL _irql;	\
	\
	IoSetCompletionRoutine((aIrp), _GeneralIrpComplete, (aEvent), TRUE, TRUE, TRUE);	\
	KeRaiseIrql(DISPATCH_LEVEL, &_irql);	\
	(aIosb)->Status = (aCall);	\
	KeLowerIrql(_irql);	\
} while (FALSE)	\

static
NTSTATUS
_TestSocket(
	_In_ PWSK_SOCKET Socket,
	_In_ PIRP Irp
)
{
	KEVENT event;
	IO_STATUS_BLOCK iosb;
	WSK_BUF msg;
	PVOID msgFlat = NULL;
	WSK_BUF recvMsg;
	PVOID recvFlat = NULL;
	PIRP recvIrp = NULL;
	KEVENT recvEvent;
	ULONG hashObjectSize = 0;
	ULONG returnedLength = 0;
	void *hashObject = NULL;
	BCRYPT_HASH_HANDLE hashHandle = NULL;
	BOOLEAN verified = FALSE;
	BCRYPT_ALG_HANDLE sha256Handle = NULL;
	DEBUG_ENTER_FUNCTION("Socket=0x%p; Irp=0x%p", Socket, Irp);

	recvIrp = IoAllocateIrp(1, FALSE);
	if (!recvIrp) {
		iosb.Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	KeInitializeEvent(&recvEvent, NotificationEvent, FALSE);
	KeInitializeEvent(&event, NotificationEvent, FALSE);
	iosb.Status = BCryptOpenAlgorithmProvider(&sha256Handle, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);
	if (!NT_SUCCESS(iosb.Status)) {
		DEBUG_ERROR("Unable to open SHA256 provider: 0x%x", iosb.Status);
		goto FreeRecvIrp;
	}

	iosb.Status = BCryptGetProperty(sha256Handle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(hashObjectSize), &returnedLength, 0);
	if (!NT_SUCCESS(iosb.Status)) {
		DEBUG_ERROR("BCryptGetProperty: 0x%x", iosb.Status);
		goto CloseProvider;
	}

	hashObject = ExAllocatePoolWithTag(NonPagedPool, hashObjectSize, VIOWSK_TEST_MSG_TAG);
	if (!hashObject) {
		iosb.Status = STATUS_INSUFFICIENT_RESOURCES;
		goto CloseProvider;
	}

	for (size_t i = 0; i < 16; ++i) {
		BOOLEAN dataSent = FALSE;
		
		if (!NT_SUCCESS(iosb.Status))
			break;

		iosb.Status = VioWskMessageGenerate(NULL, &recvMsg, &recvFlat);
		if (!NT_SUCCESS(iosb.Status)) {
			DEBUG_ERROR("VioWskMessageGenerate: 0x%x", iosb.Status);
			continue;
		}

		iosb.Status = BCryptCreateHash(sha256Handle, &hashHandle, hashObject, hashObjectSize, NULL, 0, 0);
		if (!NT_SUCCESS(iosb.Status)) {
			DEBUG_ERROR("BCryptCreateHash: 0x%x", iosb.Status);
			goto FreeRecvMessage;
		}

		iosb.Status = VioWskMessageGenerate(hashHandle, &msg, &msgFlat);
		BCryptDestroyHash(hashObject);
		if (!NT_SUCCESS(iosb.Status)) {
			DEBUG_ERROR("Unable to generate test message: 0x%x", iosb.Status);
			goto FreeRecvMessage;
		}

		iosb.Status = BCryptCreateHash(sha256Handle, &hashHandle, hashObject, hashObjectSize, NULL, 0, 0);
		if (!NT_SUCCESS(iosb.Status)) {
			DEBUG_ERROR("BCryptCreateHash: 0x%x", iosb.Status);
			goto FreeMessage;
		}

		iosb.Status = VIoWskMessageVerify(hashHandle, &msg, &verified);
		BCryptDestroyHash(hashObject);
		if (!NT_SUCCESS(iosb.Status) || !verified) {
			if (!verified) {
				iosb.Status = STATUS_UNSUCCESSFUL;
				DEBUG_ERROR("Generated test message is invalid: 0x%x", iosb.Status);
			} else {
				DEBUG_ERROR("Unable to verify test message: 0x%x", iosb.Status);
			}

			goto FreeMessage;
		}

		IoSetCompletionRoutine(Irp, _GeneralIrpComplete, &event, TRUE, TRUE, TRUE);
		iosb.Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskSend(Socket, &msg, 0, Irp);
		if (!NT_SUCCESS(iosb.Status)) {
			DEBUG_ERROR("Unable send the tes message: 0x%x", iosb.Status);
			goto FreeMessage;
		}

		dataSent = TRUE;
		while (NT_SUCCESS(iosb.Status) && recvMsg.Length > 0) {
			WSK_SYNCHRONOUS_CALL(recvIrp, &recvEvent, ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskReceive(Socket, &recvMsg, 0, recvIrp), &iosb);
			if (!NT_SUCCESS(iosb.Status) || recvMsg.Length != iosb.Information) {
				DEBUG_ERROR("Unable receive the tes message: 0x%x (%zu bytes length, %zu bytes received)", iosb.Status, recvMsg.Length, iosb.Information);
				goto FreeMessage;
			}

			VioWskMessageAdvance(&recvMsg, iosb.Information);
		}

		iosb.Status = BCryptCreateHash(sha256Handle, &hashHandle, hashObject, hashObjectSize, NULL, 0, 0);
		if (!NT_SUCCESS(iosb.Status)) {
			DEBUG_ERROR("BCryptCreateHash: 0x%x", iosb.Status);
			goto FreeMessage;
		}

		iosb.Status = VIoWskMessageVerifyBuffer(hashHandle, recvFlat, &verified);
		BCryptDestroyHash(hashObject);
		if (!NT_SUCCESS(iosb.Status) || !verified) {
			if (!verified)
				iosb.Status = STATUS_UNSUCCESSFUL;

			DEBUG_ERROR("Unable to verify test message: 0x%x", iosb.Status);
			goto FreeMessage;
		}

	FreeMessage:
		if (dataSent) {
			KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
			iosb = Irp->IoStatus;
			IoReuseIrp(Irp, STATUS_UNSUCCESSFUL);
			KeResetEvent(&event);
			if (!NT_SUCCESS(iosb.Status)) {
				DEBUG_ERROR("WskSend: 0x%x", iosb.Status);
			}
		}

		VioWskMessageFree(&msg, msgFlat);
	FreeRecvMessage:
		VioWskMessageFree(&recvMsg, recvFlat);
	}

	ExFreePoolWithTag(hashObject, VIOWSK_TEST_MSG_TAG);
CloseProvider:
	BCryptCloseAlgorithmProvider(sha256Handle, 0);
FreeRecvIrp:
	IoFreeIrp(recvIrp);
Exit:
	DEBUG_EXIT_FUNCTION("0x%x", iosb.Status);
	return iosb.Status;
}


typedef struct _TEST_THREAD_CONTEXT {
	LIST_ENTRY Entry;
	PKSPIN_LOCK ListLock;
	PETHREAD Thread;
	PIRP Irp;
	PWSK_SOCKET Socket;
	volatile LONG Terminated;
} TEST_THREAD_CONTEXT, *PTEST_THREAD_CONTEXT;

static
NTSTATUS
_SocketTestThreadCreate(
	_In_ PWSK_SOCKET Socket,
	_In_ PLIST_ENTRY ListHead,
	_In_ PKSPIN_LOCK ListLock
);

static
void
_TestThreadRoutine(
	_In_ PVOID Context
)
{
	KIRQL irql;
	BOOLEAN isActive = FALSE;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PTEST_THREAD_CONTEXT ctx = (PTEST_THREAD_CONTEXT)Context;
	DEBUG_ENTER_FUNCTION("Context=0x%p", Context);

	Status = _TestSocket(ctx->Socket, ctx->Irp);
	KeAcquireSpinLock(ctx->ListLock, &irql);
	if (!IsListEmpty(&ctx->Entry)) {
		RemoveEntryList(&ctx->Entry);
		isActive = TRUE;
	}

	KeReleaseSpinLock(ctx->ListLock, irql);
	if (isActive) {
		ObDereferenceObject(ctx->Thread);
		IoFreeIrp(ctx->Irp);
		ExFreePoolWithTag(ctx, 0);
	}

	DEBUG_EXIT_FUNCTION("0x%x", Status);
	return;
}


static
void
_ServerThreadRoutine(
	_In_opt_ PVOID Context
)
{
	KIRQL irql;
	KEVENT event;
	PIRP irp = NULL;
	SOCKADDR_VM listenAddress;
	DECLARE_UNICODE_STRING_SIZE(listenHost, 16);
	DECLARE_UNICODE_STRING_SIZE(listenPort, 16);
	PADDRINFOEXW addrInfo = NULL;
	PWSK_SOCKET serverSocket = NULL;
	IO_STATUS_BLOCK iosb;
	KSPIN_LOCK threadListLock;
	LIST_ENTRY threadListHead;
	DEBUG_ENTER_FUNCTION("Context=0x%p", Context);

	if (InterlockedIncrement(&_readyThreads) == (CLIENT_THREAD_COUNT + SERVER_THREAD_COUNT))
		KeSetEvent(&_initEvent, IO_NO_INCREMENT, FALSE);
	
	irp = IoAllocateIrp(1, FALSE);
	if (!irp) {
		iosb.Status = STATUS_INSUFFICIENT_RESOURCES;
		DEBUG_ERROR("Unable to allocate IRP: 0x%x", iosb.Status);
		goto Exit;
	}

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	WSK_SYNCHRONOUS_CALL(irp, &event, _vioWskProviderNPI.Dispatch->WskSocket(_vioWskProviderNPI.Client, AF_VSOCK, SOCK_STREAM, 0, WSK_FLAG_LISTEN_SOCKET, NULL, NULL, NULL, NULL, NULL, irp), &iosb);
	if (!NT_SUCCESS(iosb.Status)) {
		DEBUG_ERROR("Unable to create server socket: 0x%x", iosb.Status);
		goto FreeIrp;
	}

	serverSocket = (PWSK_SOCKET)iosb.Information;
	iosb.Status = RtlUnicodeStringPrintf(&listenHost, L"%u", (ULONG)VMADDR_CID_ANY);
	if (!NT_SUCCESS(iosb.Status)) {
		DEBUG_ERROR("Unable to prepare server address hos: 0x%x", iosb.Status);
		goto CloseSocket;
	}

	iosb.Status = RtlUnicodeStringPrintf(&listenPort, L"%zu", LISTEN_PORT_MIN + (SIZE_T)Context);
	if (!NT_SUCCESS(iosb.Status)) {
		DEBUG_ERROR("Unable to prepare server address port: 0x%x", iosb.Status);
		goto CloseSocket;
	}

	WSK_SYNCHRONOUS_CALL(irp, &event, _vioWskProviderNPI.Dispatch->WskGetAddressInfo(_vioWskProviderNPI.Client, &listenHost, &listenPort, 0, NULL, NULL, &addrInfo, NULL, NULL, irp), &iosb);
	if (!NT_SUCCESS(iosb.Status)) {
		DEBUG_ERROR("Unable to translate the listen address: 0x%x", iosb.Status);
		goto CloseSocket;
	}

	listenAddress = *(PSOCKADDR_VM)addrInfo->ai_addr;
	_vioWskProviderNPI.Dispatch->WskFreeAddressInfo(_vioWskProviderNPI.Client, addrInfo);

	WSK_SYNCHRONOUS_CALL(irp, &event, ((PWSK_PROVIDER_LISTEN_DISPATCH)serverSocket->Dispatch)->WskBind(serverSocket, (PSOCKADDR)&listenAddress, 0, irp), &iosb);
	if (!NT_SUCCESS(iosb.Status)) {
		DEBUG_ERROR("Unable to bind: 0x%x", iosb.Status);
		goto CloseSocket;
	}

	InitializeListHead(&threadListHead);
	KeInitializeSpinLock(&threadListLock);
	while (!InterlockedCompareExchange(&_terminate, 1, 1)) {
		PWSK_SOCKET clientSocket = NULL;
		SOCKADDR_VM localAddr;
		SOCKADDR_VM remoteAddr;
		LARGE_INTEGER timeout;

		timeout.QuadPart = -10000000;
		WSK_ASYNCHRONOUS_CALL(irp, &event, ((PWSK_PROVIDER_LISTEN_DISPATCH)serverSocket->Dispatch)->WskAccept(serverSocket, WSK_FLAG_CONNECTION_SOCKET, NULL, NULL, (PSOCKADDR)&localAddr, (PSOCKADDR)&remoteAddr, irp), &iosb);
		if (!NT_SUCCESS(iosb.Status)) {
			DEBUG_ERROR("Unable to accept: 0x%x", iosb.Status);
			KeDelayExecutionThread(KernelMode, FALSE, &timeout);
			continue;
		}

		if (iosb.Status == STATUS_PENDING) {
			do {
				iosb.Status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &timeout);
			} while (iosb.Status == STATUS_TIMEOUT && !InterlockedCompareExchange(&_terminate, 1, 1));
		}

		if (iosb.Status == STATUS_TIMEOUT)
			break;
		
		KeResetEvent(&event);
		clientSocket = (PWSK_SOCKET)irp->IoStatus.Information;
		IoReuseIrp(irp, STATUS_UNSUCCESSFUL);
		WSK_SYNCHRONOUS_CALL(irp, &event, _vioWskProviderNPI.Dispatch->WskGetNameInfo(_vioWskProviderNPI.Client, (PSOCKADDR)&localAddr, sizeof(localAddr), &listenHost, &listenPort, 0, NULL, NULL, irp), &iosb);
		if (NT_SUCCESS(iosb.Status)) {
			DEBUG_INFO("Accepted connection:");
			DEBUG_INFO("  Local: %wZ:%wZ", &listenHost, &listenPort);
			WSK_SYNCHRONOUS_CALL(irp, &event, _vioWskProviderNPI.Dispatch->WskGetNameInfo(_vioWskProviderNPI.Client, (PSOCKADDR)&remoteAddr, sizeof(remoteAddr), &listenHost, &listenPort, 0, NULL, NULL, irp), &iosb);
			if (!NT_SUCCESS(iosb.Status)) {
				DEBUG_ERROR("Unable to get client address strings: 0x%x", iosb.Status);
			}
		}

		if (NT_SUCCESS(iosb.Status)) {
			DEBUG_INFO("  Remote: %wZ:%wZ", &listenHost, &listenPort);
			iosb.Status = _SocketTestThreadCreate(clientSocket, &threadListHead, &threadListLock);
			if (!NT_SUCCESS(iosb.Status)) {
				DEBUG_ERROR("Socket test thread failed to create: 0x%x", iosb.Status);
			}
		}

		if (!NT_SUCCESS(iosb.Status)) {
			WSK_SYNCHRONOUS_CALL(irp, &event, ((PWSK_PROVIDER_BASIC_DISPATCH)clientSocket->Dispatch)->WskCloseSocket(clientSocket, irp), &iosb);
			KeDelayExecutionThread(KernelMode, FALSE, &timeout);
			continue;
		}
	}

	KeAcquireSpinLock(&threadListLock, &irql);
	while (!IsListEmpty(&threadListHead)) {
		PTEST_THREAD_CONTEXT ctx = CONTAINING_RECORD(threadListHead.Flink, TEST_THREAD_CONTEXT, Entry);
	
		RemoveEntryList(&ctx->Entry);
		InitializeListHead(&ctx->Entry);
		KeReleaseSpinLock(&threadListLock, irql);
		InterlockedExchange(&ctx->Terminated, 1);
		KeWaitForSingleObject(ctx->Thread, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(ctx->Thread);
		ExFreePoolWithTag(ctx, 0);
		KeAcquireSpinLock(&threadListLock, &irql);
	}

	KeReleaseSpinLock(&threadListLock, irql);
CloseSocket:
	WSK_SYNCHRONOUS_CALL(irp, &event, ((PWSK_PROVIDER_BASIC_DISPATCH)serverSocket->Dispatch)->WskCloseSocket(serverSocket, irp), &iosb);
	if (!NT_SUCCESS(iosb.Status)) {
		DEBUG_ERROR("Unable to close the server socket: 0x%x", iosb.Status);
	}
FreeIrp:
	IoFreeIrp(irp);
Exit:
	InterlockedExchange(&_terminate, 1);

	DEBUG_EXIT_FUNCTION("0x%x", iosb.Status);
	return;
}


static
void
_ClientThreadRoutine(
	_In_opt_ PVOID Context
)
{
	KEVENT event;
	PIRP irp = NULL;
	LARGE_INTEGER timeSeed;
	LARGE_INTEGER timeout;
	IO_STATUS_BLOCK iosb;
	SOCKADDR_VM localAddr;
	SOCKADDR_VM remoteAddr;
	PWSK_SOCKET socket = NULL;
	DEBUG_ENTER_FUNCTION("Context=0x%p", Context);

	iosb.Status = STATUS_SUCCESS;
	if (InterlockedIncrement(&_readyThreads) == (CLIENT_THREAD_COUNT + SERVER_THREAD_COUNT))
		KeSetEvent(&_initEvent, IO_NO_INCREMENT, FALSE);

	irp = IoAllocateIrp(1, FALSE);
	if (!irp) {
		iosb.Status = STATUS_INSUFFICIENT_RESOURCES;
		DEBUG_ERROR("Failed to allocate IRP: 0x%x", iosb.Status);
		goto Exit;
	}

	timeout.QuadPart = -10000000;
	KeQuerySystemTime(&timeSeed);
	KeInitializeEvent(&event, NotificationEvent, FALSE);
	while (!InterlockedCompareExchange(&_terminate, 1, 1)) {
		memset(&localAddr, 0, sizeof(localAddr));
		localAddr.svm_family = AF_VSOCK;
		localAddr.svm_cid = (UINT)VMADDR_CID_ANY;
		localAddr.svm_port = (UINT)VMADDR_PORT_ANY;
		memset(&remoteAddr, 0, sizeof(remoteAddr));
		remoteAddr.svm_family = AF_VSOCK;
		remoteAddr.svm_cid = (UINT)VMADDR_CID_ANY;
		remoteAddr.svm_port = LISTEN_PORT_MIN + (RtlRandomEx(&timeSeed.LowPart) % (SERVER_THREAD_COUNT));
		WSK_SYNCHRONOUS_CALL(irp, &event, _vioWskProviderNPI.Dispatch->WskSocket(_vioWskProviderNPI.Client, AF_VSOCK, SOCK_STREAM, 0, WSK_FLAG_CONNECTION_SOCKET, NULL, NULL, NULL, NULL, NULL, irp), &iosb);
		if (!NT_SUCCESS(iosb.Status)) {
			DEBUG_ERROR("Unable to create client socket: 0x%x", iosb.Status);
			break;
		}

		socket = (PWSK_SOCKET)iosb.Information;
		WSK_SYNCHRONOUS_CALL(irp, &event, ((PWSK_PROVIDER_CONNECTION_DISPATCH)socket->Dispatch)->WskBind(socket, (PSOCKADDR)&localAddr, 0, irp), &iosb);
		if (NT_SUCCESS(iosb.Status))
        {
            WSK_SYNCHRONOUS_CALL(irp, &event, ((PWSK_PROVIDER_CONNECTION_DISPATCH)socket->Dispatch)->WskConnect(socket, (PSOCKADDR)&remoteAddr, 0, irp), &iosb);
        }

        if (NT_SUCCESS(iosb.Status)) {
			iosb.Status = _TestSocket(socket, irp);
			if (!NT_SUCCESS(iosb.Status)) {
				DEBUG_ERROR("Client socket test failed: 0x%x", iosb.Status);
			}
			
			WSK_SYNCHRONOUS_CALL(irp, &event, ((PWSK_PROVIDER_CONNECTION_DISPATCH)socket->Dispatch)->WskDisconnect(socket, NULL, 0, irp), &iosb);
			if (!NT_SUCCESS(iosb.Status)) {
				DEBUG_ERROR("Client socket disconnect failed: 0x%x", iosb.Status);
			}
		} else {
			DEBUG_ERROR("Unable to connect to the server: 0x%x", iosb.Status);
		}

		WSK_SYNCHRONOUS_CALL(irp, &event, ((PWSK_PROVIDER_CONNECTION_DISPATCH)socket->Dispatch)->WskCloseSocket(socket, irp), &iosb);
		if (!NT_SUCCESS(iosb.Status)) {
			DEBUG_ERROR("Unable to close the client socket: 0x%x", iosb.Status);
		}

		KeDelayExecutionThread(KernelMode, FALSE, &timeout);
	}

	IoFreeIrp(irp);
Exit:
	InterlockedExchange(&_terminate, 1);

	DEBUG_EXIT_FUNCTION("0x%x", iosb.Status);
	return;
}


static
void
_DestroyThreadGroup(
	_In_ PETHREAD* ObjectArray,
	_In_ SIZE_T Count
)
{
	DEBUG_ENTER_FUNCTION("ObjectArray=0x%p; Count=%zu", ObjectArray, Count);

	_terminate = TRUE;
	for (SIZE_T i = 0; i < Count; ++i) {
		KeWaitForSingleObject(ObjectArray[i], Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(ObjectArray[i]);
	}

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}


static
NTSTATUS
_CreateThreadGroup(
	_In_ SIZE_T Count,
	_In_ PKSTART_ROUTINE Routine,
	_Out_ PETHREAD *ObjectArray
)
{
	CLIENT_ID clientId;
	OBJECT_ATTRIBUTES oa;
	HANDLE hThread = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("Count=%zu; Routine=0x%p; ObjectArray=0x%p", Count, Routine, ObjectArray);

	InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	for (SIZE_T i = 0; i < Count; ++i) {
		Status = PsCreateSystemThread(&hThread, SYNCHRONIZE, &oa, NULL, &clientId, Routine, (PVOID)i);
		if (NT_SUCCESS(Status)) {
			Status = ObReferenceObjectByHandle(hThread, SYNCHRONIZE, *PsThreadType, KernelMode, ObjectArray + i, NULL);
			ZwClose(hThread);
		}

		if (!NT_SUCCESS(Status)) {
			_DestroyThreadGroup(ObjectArray, i);
			break;
		}
	}

	DEBUG_EXIT_FUNCTION("0x%x", Status);
	return Status;
}


static
NTSTATUS
_SocketTestThreadCreate(
	_In_ PWSK_SOCKET Socket,
	_In_ PLIST_ENTRY ListHead,
	_In_ PKSPIN_LOCK ListLock
)
{
	KIRQL irql;
	CLIENT_ID clientId;
	OBJECT_ATTRIBUTES oa;
	HANDLE hThread = NULL;
	PTEST_THREAD_CONTEXT ctx = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("Socket=0x%p; ListHead=0x%p; ListLock=0x%p", Socket, ListHead, ListLock);

	ctx = ExAllocatePoolWithTag(PagedPool, sizeof(TEST_THREAD_CONTEXT), 0);
	if (!ctx) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	InterlockedExchange(&ctx->Terminated, 0);
	InitializeListHead(&ctx->Entry);
	ctx->ListLock = ListLock;
	ctx->Socket = Socket;
	ctx->Irp = IoAllocateIrp(1, FALSE);
	if (!ctx->Irp) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto FreeCtx;
	}

	InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = PsCreateSystemThread(&hThread, SYNCHRONIZE, &oa, NULL, &clientId, _TestThreadRoutine, ctx);
	if (!NT_SUCCESS(Status))
		goto FreeIrp;;

	Status = ObReferenceObjectByHandle(hThread, SYNCHRONIZE, *PsThreadType, KernelMode, &ctx->Thread, NULL);
	if (!NT_SUCCESS(Status)) {
		InterlockedExchange(&ctx->Terminated, 1);
		ZwWaitForSingleObject(hThread, FALSE, NULL);
		goto CloseThread;
	}

	KeAcquireSpinLock(ListLock, &irql);
	InsertTailList(ListHead, &ctx->Entry);
	KeReleaseSpinLock(ListLock, irql);
	ctx = NULL;
CloseThread:
	ZwClose(hThread);
FreeIrp:
	if (ctx && ctx->Irp)
		IoFreeIrp(ctx->Irp);
FreeCtx:
	if (ctx)
		ExFreePoolWithTag(ctx, 0);
Exit:
	DEBUG_EXIT_FUNCTION("0x%x", Status);
	return Status;
}


static
void
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p", DriverObject);

	_DestroyThreadGroup(_clientThreads, sizeof(_clientThreads) / sizeof(_clientThreads[0]));
	_DestroyThreadGroup(_serverThreads, sizeof(_serverThreads) / sizeof(_serverThreads[0]));
	VioWskReleaseProviderNPI(&_vioWskRegistration);
	VioWskDeregister(&_vioWskRegistration);
	VioWskModuleFinit();
	IoDeleteDevice(_shutdownDeviceObject);

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}


NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	PDEVICE_OBJECT Device = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p; RegistryPath=\"%wZ\"", DriverObject, RegistryPath);

	Status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &Device);
	if (!NT_SUCCESS(Status))
		goto Exit;

	Status = VioWskModuleInit(DriverObject, RegistryPath, Device);
	if (!NT_SUCCESS(Status))
		goto DeleteDevice;

	Status = VioWskRegister(&_vioWskClientNPI, &_vioWskRegistration);
	if (!NT_SUCCESS(Status))
		goto VioWskFinit;

	Status = VioWskCaptureProviderNPI(&_vioWskRegistration, WSK_INFINITE_WAIT, &_vioWskProviderNPI);
	if (!NT_SUCCESS(Status))
		goto VioWskDeregister;

	KeInitializeEvent(&_initEvent, NotificationEvent, FALSE);
	Status = _CreateThreadGroup(sizeof(_serverThreads) / sizeof(_serverThreads[0]), _ServerThreadRoutine, _serverThreads);
	if (!NT_SUCCESS(Status))
		goto VIoWskReleaseNPI;

	Status = _CreateThreadGroup(sizeof(_clientThreads) / sizeof(_clientThreads[0]), _ClientThreadRoutine, _clientThreads);
	if (!NT_SUCCESS(Status))
		goto DestroyServers;

	KeWaitForSingleObject(&_initEvent, Executive, KernelMode, FALSE, NULL);
	if (_terminate) {
		Status = STATUS_UNSUCCESSFUL;
		goto DestroyClients;
	}

	DriverObject->DriverUnload = DriverUnload;
	_shutdownDeviceObject = (PDEVICE_OBJECT)InterlockedExchangePointer(&Device, NULL);
DestroyClients:
	if (!NT_SUCCESS(Status))
		_DestroyThreadGroup(_clientThreads, sizeof(_clientThreads) / sizeof(_clientThreads[0]));
DestroyServers:
	if (!NT_SUCCESS(Status))
		_DestroyThreadGroup(_serverThreads, sizeof(_serverThreads) / sizeof(_serverThreads[0]));
VIoWskReleaseNPI:
	if (!NT_SUCCESS(Status))
		VioWskReleaseProviderNPI(&_vioWskRegistration);
VioWskDeregister:
	if (!NT_SUCCESS(Status))
		VioWskDeregister(&_vioWskRegistration);
VioWskFinit:
	if (!NT_SUCCESS(Status))
		VioWskModuleFinit();
DeleteDevice:
	if (Device)
		IoDeleteDevice(Device);
Exit:
	DEBUG_EXIT_FUNCTION("0x%x", Status);
	DbgBreakPoint();
	return Status;
}