/*
 * Socket dispatch functions
 *
 * Copyright (c) 2021 Virtuozzo International GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "precomp.h"
#include "..\inc\debug-utils.h"
#include "viowsk.h"
#include "wsk-utils.h"
#include "viowsk-internal.h"
#include "wsk-completion.h"
#include "wsk-workitem.h"
#include "wsk-mdl.h"
#include "..\inc\vio_wsk.h"

NTSTATUS
WSKAPI
VioWskControlSocket(
    _In_ PWSK_SOCKET                         Socket,
    _In_ WSK_CONTROL_SOCKET_TYPE             RequestType,
    _In_ ULONG                               ControlCode,
    _In_ ULONG                               Level,
    _In_ SIZE_T                              InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID    InputBuffer,
    _In_ SIZE_T                              OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID OutputBuffer,
    _Out_opt_ SIZE_T                        *OutputSizeReturned,
    _Inout_opt_ PIRP                         Irp
);

NTSTATUS
WSKAPI
VioWskCloseSocket(
    _In_ PWSK_SOCKET Socket,
    _Inout_ PIRP     Irp
);

NTSTATUS
WSKAPI
VioWskBind(
    _In_ PWSK_SOCKET Socket,
    _In_ PSOCKADDR   LocalAddress,
    _Reserved_ ULONG Flags,
    _Inout_ PIRP     Irp
    );

NTSTATUS
WSKAPI
VioWskAccept(
    _In_ PWSK_SOCKET                               ListenSocket,
    _Reserved_ ULONG                               Flags,
    _In_opt_ PVOID                                 AcceptSocketContext,
    _In_opt_ CONST WSK_CLIENT_CONNECTION_DISPATCH *AcceptSocketDispatch,
    _Out_opt_ PSOCKADDR                            LocalAddress,
    _Out_opt_ PSOCKADDR                            RemoteAddress,
    _Inout_ PIRP                                   Irp
    );

NTSTATUS
WSKAPI
VioWskInspectComplete(
    _In_ PWSK_SOCKET        ListenSocket,
    _In_ PWSK_INSPECT_ID    InspectID,
    _In_ WSK_INSPECT_ACTION Action,
    _Inout_ PIRP            Irp
    );

NTSTATUS
WSKAPI
VioWskGetLocalAddress(
    _In_ PWSK_SOCKET Socket,
    _Out_ PSOCKADDR  LocalAddress,
    _Inout_ PIRP     Irp
    );

NTSTATUS
WSKAPI
VioWskConnect(
    _In_ PWSK_SOCKET Socket,
    _In_ PSOCKADDR   RemoteAddress,
    _Reserved_ ULONG Flags,
    _Inout_ PIRP     Irp
    );


NTSTATUS
WSKAPI
VioWskGetRemoteAddress(
    _In_ PWSK_SOCKET Socket,
    _Out_ PSOCKADDR  RemoteAddress,
    _Inout_ PIRP     Irp
    );

NTSTATUS
WSKAPI
VioWskSend(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF    Buffer,
    _In_ ULONG       Flags,
    _Inout_ PIRP     Irp
    );

NTSTATUS
WSKAPI
VioWskReceive(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF    Buffer,
    _In_ ULONG       Flags,
    _Inout_ PIRP     Irp
    );

NTSTATUS
WSKAPI
VioWskDisconnect(
    _In_ PWSK_SOCKET  Socket,
    _In_opt_ PWSK_BUF Buffer,
    _In_ ULONG        Flags,
    _Inout_ PIRP      Irp
    );

NTSTATUS
WSKAPI
VioWskRelease(
    _In_ PWSK_SOCKET          Socket,
    _In_ PWSK_DATA_INDICATION DataIndication
    );

NTSTATUS
WSKAPI
VioWskConnectEx(
    _In_ PWSK_SOCKET  Socket,
    _In_ PSOCKADDR    RemoteAddress,
    _In_opt_ PWSK_BUF Buffer,
    _Reserved_ ULONG  Flags,
    _Inout_ PIRP      Irp
    );

NTSTATUS
WSKAPI
VioWskSendEx(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF    Buffer,
    _In_ ULONG       Flags,
    _In_ ULONG       ControlInfoLength,
    _In_reads_bytes_opt_(ControlInfoLength) PCMSGHDR ControlInfo,
    _Inout_ PIRP     Irp
    );

NTSTATUS
WSKAPI
VioWskReceiveEx(
    _In_ PWSK_SOCKET   Socket,
    _In_ PWSK_BUF      Buffer,
    _In_ ULONG         Flags,
    _Inout_opt_ PULONG ControlInfoLength,
    _Out_writes_bytes_opt_(*ControlInfoLength) PCMSGHDR ControlInfo,
    _Reserved_ PULONG  ControlFlags,
    _Inout_ PIRP       Irp
    );

NTSTATUS
WSKAPI
VioWskListen(
    _In_ PWSK_SOCKET Socket,
    _Inout_ PIRP     Irp
    );

//////////////////////////////////////////////////////////////////////////
WSK_PROVIDER_BASIC_DISPATCH gBasicDispatch =
{
    VioWskControlSocket,
    VioWskCloseSocket
};

WSK_PROVIDER_LISTEN_DISPATCH gListenDispatch =
{
    {
        VioWskControlSocket,
        VioWskCloseSocket
    },
    VioWskBind,
    VioWskAccept,
    VioWskInspectComplete,
    VioWskGetLocalAddress
};

WSK_PROVIDER_CONNECTION_DISPATCH gConnectionDispatch =
{
    {
        VioWskControlSocket,
        VioWskCloseSocket
    },
    VioWskBind,
    VioWskConnect,
    VioWskGetLocalAddress,
    VioWskGetRemoteAddress,
    VioWskSend,
    VioWskReceive,
    VioWskDisconnect,
    VioWskRelease,
    VioWskConnectEx,
    VioWskSendEx,
    VioWskReceiveEx
};

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
WSK_PROVIDER_STREAM_DISPATCH gStreamDispatch =
{
    {
        VioWskControlSocket,
        VioWskCloseSocket
    },
    VioWskBind,
    VioWskAccept,
    VioWskConnect,
    VioWskListen,
    VioWskSend,
    VioWskReceive,
    VioWskDisconnect,
    VioWskRelease,
    VioWskGetLocalAddress,
    VioWskGetRemoteAddress,
    VioWskConnectEx,
    VioWskSendEx,
    VioWskReceiveEx
};
#endif // if (NTDDI_VERSION >= NTDDI_WIN10_RS2)

//////////////////////////////////////////////////////////////////////////
NTSTATUS
WSKAPI
VioWskControlSocket(
    _In_ PWSK_SOCKET                          Socket,
    _In_ WSK_CONTROL_SOCKET_TYPE              RequestType,
    _In_ ULONG                                ControlCode,
    _In_ ULONG                                Level,
    _In_ SIZE_T                               InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID     InputBuffer,
    _In_ SIZE_T                               OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID  OutputBuffer,
    _Out_opt_ SIZE_T                         *OutputSizeReturned,
    _Inout_opt_ PIRP                          Irp
)
{
    PIRP IOCTLIrp = NULL;
    PVIOSOCKET_COMPLETION_CONTEXT CompContext = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PKEVENT pEvent = NULL;
    KEVENT Event;
    PIO_STATUS_BLOCK pIoStatusBlock = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    PVIOWSK_SOCKET pSocket = CONTAINING_RECORD(Socket, VIOWSK_SOCKET, WskSocket);
    DEBUG_ENTER_FUNCTION("Socket=0x%p; RequestType=%u; ControlCode=0x%x; Level=%u; InputSize=%zu; InputBuffer=0x%p; OutputSize=%zu; OutputBuffer=0x%p; OutputSizeReturned=0x%p; Irp=0x%p", Socket, RequestType, ControlCode, Level, InputSize, InputBuffer, OutputSize, OutputBuffer, OutputSizeReturned, Irp);

    UNREFERENCED_PARAMETER(OutputSizeReturned);

    if (!Irp)
    {
        Irp = IoAllocateIrp(1, FALSE);
        if (!Irp)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        KeInitializeEvent(&Event, NotificationEvent, FALSE);
        pEvent = &Event;
        pIoStatusBlock = &IoStatusBlock;
    }

    Status = VioWskIrpAcquire(pSocket, Irp);
    if (!NT_SUCCESS(Status))
    {
        pSocket = NULL;
        if (pEvent)
            IoSetNextIrpStackLocation(Irp);

        goto CompleteIrp;
    }

    switch (RequestType)
    {
    case WskSetOption:
    case WskGetOption: {
        ULONG ioctl = 0;
        VIRTIO_VSOCK_OPT Opt;

        memset(&Opt, 0, sizeof(Opt));
        Opt.level = Level;
        Opt.optname = ControlCode;
        switch (RequestType)
        {
        case WskSetOption:
            ioctl = IOCTL_SOCKET_SET_SOCK_OPT;
            Opt.optval = (ULONGLONG)InputBuffer;
            Opt.optlen = (int)InputSize;
            break;
        case WskGetOption:
            ioctl = IOCTL_SOCKET_GET_SOCK_OPT;
            Opt.optval = (ULONGLONG)OutputBuffer;
            Opt.optlen = (int)OutputSize;
            break;
        }

        Status = VioWskSocketBuildIOCTL(pSocket, ioctl, &Opt, sizeof(Opt), &Opt, sizeof(Opt), &IOCTLIrp);
    } break;
    case WskIoctl: {
        VIRTIO_VSOCK_IOCTL_IN params;

        params.dwIoControlCode = ControlCode;
        params.lpvInBuffer = (ULONGLONG)InputBuffer;
        params.cbInBuffer = (ULONG)InputSize;
        Status = VioWskSocketBuildIOCTL(pSocket, IOCTL_SOCKET_IOCTL, &params, sizeof(params), OutputBuffer, (ULONG)OutputSize, &IOCTLIrp);
    } break;
    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    if (!NT_SUCCESS(Status))
        goto CompleteIrp;

    CompContext = WskCompContextAlloc(wsksFinished, pSocket, Irp, NULL, NULL);
    if (!CompContext)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto FreeIOCTLIrp;
    }

    CompContext->BytesReturned = OutputSizeReturned;
    CompContext->Event = pEvent;
    CompContext->IoStatusBlock = pIoStatusBlock;
    Status = CompContextSendIrp(CompContext, IOCTLIrp);
    if (NT_SUCCESS(Status))
    {
        IOCTLIrp = NULL;
        if (Status == STATUS_PENDING && pEvent)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }
    }

    WskCompContextDereference(CompContext);
    Irp = NULL;
FreeIOCTLIrp:
    if (IOCTLIrp)
        IoFreeIrp(IOCTLIrp);
CompleteIrp:
    if (Irp)
        VioWskIrpComplete(pSocket, Irp, Status, 0);

    if (pEvent)
        IoFreeIrp(Irp);
Exit:
    DEBUG_EXIT_FUNCTION("0x%x", Status);
    return Status;
}

NTSTATUS
WSKAPI
VioWskCloseSocket(
    _In_ PWSK_SOCKET Socket,
    _Inout_ PIRP     Irp
)
{
    PWSK_WORKITEM WorkItem = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVIOWSK_SOCKET pSocket = CONTAINING_RECORD(Socket, VIOWSK_SOCKET, WskSocket);
    DEBUG_ENTER_FUNCTION("Socket=0x%p; Irp=0x%p", Socket, Irp);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        WorkItem = WskWorkItemAlloc(wskwitCloseSocket, Irp);
        if (!WorkItem)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            IoSetNextIrpStackLocation(Irp);
            goto CompleteIrp;
        }

        WorkItem->Specific.CloseSocket.Socket = Socket;
        WskWorkItemQueue(WorkItem);
        Status = STATUS_PENDING;
        goto Exit;
	}

    Status = VioWskIrpAcquire(pSocket, Irp);
    if (!NT_SUCCESS(Status))
    {
        pSocket = NULL;
        goto CompleteIrp;
    }
 
    IoReleaseRemoveLockAndWait(&pSocket->CloseRemoveLock, Irp);
    VioWskCloseSocketInternal(pSocket);
    pSocket = NULL;

CompleteIrp:
	VioWskIrpComplete(pSocket, Irp, Status, 0);
Exit:
	DEBUG_EXIT_FUNCTION("0x%x", Status);
	return Status;
}

NTSTATUS
WSKAPI
VioWskBind(
    _In_ PWSK_SOCKET Socket,
    _In_ PSOCKADDR   LocalAddress,
    _Reserved_ ULONG Flags,
    _Inout_ PIRP     Irp
)
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(Flags);

    return VioWskCompleteIrp(Irp, STATUS_NOT_IMPLEMENTED, 0);
}

NTSTATUS
WSKAPI
VioWskAccept(
    _In_ PWSK_SOCKET                               ListenSocket,
    _Reserved_ ULONG                               Flags,
    _In_opt_ PVOID                                 AcceptSocketContext,
    _In_opt_ CONST WSK_CLIENT_CONNECTION_DISPATCH *AcceptSocketDispatch,
    _Out_opt_ PSOCKADDR                            LocalAddress,
    _Out_opt_ PSOCKADDR                            RemoteAddress,
    _Inout_ PIRP                                   Irp
)
{
    PIRP AddrIrp = NULL;
    PIRP CloseIrp = NULL;
    PWSK_WORKITEM CloseWorkItem = NULL;
    BOOLEAN acceptSocketAcquired = FALSE;
    PWSK_WORKITEM WorkItem = NULL;
    PVIOSOCKET_COMPLETION_CONTEXT CompContext = NULL;
    PVIOWSK_SOCKET pSocket = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVIOWSK_SOCKET pListenSocket = CONTAINING_RECORD(ListenSocket, VIOWSK_SOCKET, WskSocket);
    DEBUG_ENTER_FUNCTION("ListenSocket=0x%p; Flags=0x%x; AcceptSocketContext=0x%p; AcceptSocketDispatch=0x%p; LocalAddress=0x%p; RemoteAddress=0x%p; Irp=0x%p", ListenSocket, Flags, AcceptSocketContext, AcceptSocketDispatch, LocalAddress, RemoteAddress, Irp);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        WorkItem = WskWorkItemAlloc(wskwitAccept, Irp);
        if (!WorkItem)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            pListenSocket = NULL;
            goto CompleteIrp;
        }

        WorkItem->Specific.Accept.AcceptSocketContext = AcceptSocketContext;
        WorkItem->Specific.Accept.AcceptSocketDispatch = AcceptSocketDispatch;
        WorkItem->Specific.Accept.Flags = Flags;
        WorkItem->Specific.Accept.ListenSocket = ListenSocket;
        WorkItem->Specific.Accept.LocalAddress = LocalAddress;
        WorkItem->Specific.Accept.RemoteAddress = RemoteAddress;
        WskWorkItemQueue(WorkItem);
        Status = STATUS_PENDING;
        goto Exit;
    }

    Status = VioWskIrpAcquire(pListenSocket, Irp);
    if (!NT_SUCCESS(Status))
    {
        pListenSocket = NULL;
        goto CompleteIrp;
	}

    CloseIrp = IoAllocateIrp(1, FALSE);
    if (!CloseIrp)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto CompleteIrp;
	}

	CloseWorkItem = WskWorkItemAlloc(wskwitCloseSocket, CloseIrp);
	if (!CloseWorkItem)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto FreeCloseIrp;
	}

    CloseIrp = NULL;
    Status = VioWskSocketInternal(pListenSocket->Client, pListenSocket, Flags, AcceptSocketContext, AcceptSocketDispatch, NULL, NULL, NULL, &pSocket);
    if (!NT_SUCCESS(Status))
        goto FreeCloseWorkItem;

    if (LocalAddress || RemoteAddress)
    {
        Status = VioWskIrpAcquire(pSocket, Irp);
        if (!NT_SUCCESS(Status))
            goto CloseNewSocket;

        acceptSocketAcquired = TRUE;
        Status = VioWskSocketBuildIOCTL(pSocket, (LocalAddress ? IOCTL_SOCKET_GET_SOCK_NAME : IOCTL_SOCKET_GET_PEER_NAME), NULL, 0, (LocalAddress ? LocalAddress : RemoteAddress), sizeof(SOCKADDR_VM), &AddrIrp);
        if (!NT_SUCCESS(Status))
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto CloseNewSocket;
        }

        CloseWorkItem->Specific.CloseSocket.Socket = &pSocket->WskSocket;
        CompContext = WskCompContextAlloc((LocalAddress ? wsksAcceptLocal : wsksAcceptRemote), pSocket, Irp, NULL, NULL);
        if (!CompContext)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto FreeAddrIrp;
        }

        Irp = NULL;
        CompContext->Specific.Accept.LocalAddress = LocalAddress;
        CompContext->Specific.Accept.RemoteAddress = RemoteAddress;
        CompContext->Specific.Accept.Socket = &pSocket->WskSocket;
        CompContext->Specific.Accept.CloseWorkItem = CloseWorkItem;
        Status = CompContextSendIrp(CompContext, AddrIrp);
        WskCompContextDereference(CompContext);
        if (NT_SUCCESS(Status))
        {
            CloseWorkItem = NULL;
            AddrIrp = NULL;
        }
     }

FreeAddrIrp:
    if (AddrIrp)
        IoFreeIrp(AddrIrp);
CloseNewSocket:
    if (!NT_SUCCESS(Status))
    {
        if (acceptSocketAcquired)
            VioWskIrpRelease(pSocket, Irp);

        VioWskCloseSocketInternal(pSocket);
        pSocket = NULL;
    }
FreeCloseWorkItem:
    if (CloseWorkItem)
        WskWorkItemFree(CloseWorkItem);
FreeCloseIrp:
    if (CloseIrp)
        IoFreeIrp(CloseIrp);
CompleteIrp:
    if (Irp)
        VioWskIrpComplete(pListenSocket, Irp, Status, (ULONG_PTR)pSocket);
Exit:
    DEBUG_EXIT_FUNCTION("0x%x", Status);
    return Status;
}

NTSTATUS
WSKAPI
VioWskInspectComplete(
    _In_ PWSK_SOCKET        ListenSocket,
    _In_ PWSK_INSPECT_ID    InspectID,
    _In_ WSK_INSPECT_ACTION Action,
    _Inout_ PIRP            Irp
)
{
    UNREFERENCED_PARAMETER(ListenSocket);
    UNREFERENCED_PARAMETER(InspectID);
    UNREFERENCED_PARAMETER(Action);

    return VioWskCompleteIrp(Irp, STATUS_NOT_IMPLEMENTED, 0);
}

NTSTATUS
WSKAPI
VioWskGetLocalAddress(
    _In_ PWSK_SOCKET Socket,
    _Out_ PSOCKADDR  LocalAddress,
    _Inout_ PIRP     Irp
)
{
    PIRP IOCTLIrp = NULL;
    PVIOSOCKET_COMPLETION_CONTEXT CompContext = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVIOWSK_SOCKET pSocket = CONTAINING_RECORD(Socket, VIOWSK_SOCKET, WskSocket);
    DEBUG_ENTER_FUNCTION("Socket=0x%p; LocalAddress=0x%p; Irp=0x%p", Socket, LocalAddress, Irp);

    Status = VioWskIrpAcquire(pSocket, Irp);
    if (!NT_SUCCESS(Status))
    {
        pSocket = NULL;
        goto CompleteIrp;
    }

    Status = VioWskSocketBuildIOCTL(pSocket, IOCTL_SOCKET_GET_SOCK_NAME, NULL, 0, LocalAddress, sizeof(SOCKADDR_VM), &IOCTLIrp);
    if (!NT_SUCCESS(Status))
        goto CompleteIrp;

    CompContext = WskCompContextAlloc(wsksReadIOCTL, pSocket, Irp, NULL, NULL);
    if (!CompContext)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto FreeOpIrp;
    }

    Status = CompContextSendIrp(CompContext, IOCTLIrp);
    WskCompContextDereference(CompContext);
    if (NT_SUCCESS(Status))
        IOCTLIrp = NULL;

    Irp = NULL;

FreeOpIrp:
    if (IOCTLIrp)
        IoFreeIrp(IOCTLIrp);
CompleteIrp:
    if (Irp)
        VioWskIrpComplete(pSocket, Irp, Status, 0);

    DEBUG_EXIT_FUNCTION("0x%x", Status);
    return Status;
}

NTSTATUS
WSKAPI
VioWskConnect(
    _In_ PWSK_SOCKET Socket,
    _In_ PSOCKADDR   RemoteAddress,
    _Reserved_ ULONG Flags,
    _Inout_ PIRP     Irp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SOCKADDR_VM VMRemoteAddr;
    PVIOWSK_SOCKET pSocket = CONTAINING_RECORD(Socket, VIOWSK_SOCKET, WskSocket);
    DEBUG_ENTER_FUNCTION("Socket=0x%p; RemoteAddress=0x%p; Flags=0x%x; Irp=0x%p", Socket, RemoteAddress, Flags, Irp);

    UNREFERENCED_PARAMETER(Flags);

    VMRemoteAddr = *(PSOCKADDR_VM)RemoteAddress;
    if (VMRemoteAddr.svm_cid == VMADDR_CID_ANY)
        VMRemoteAddr.svm_cid = pSocket->GuestId;

    Status = VioWskIrpAcquire(pSocket, Irp);
    if (!NT_SUCCESS(Status))
    {
        pSocket = NULL;
        goto CompleteIrp;
    }

    Status = VioWskSocketIOCTL(pSocket, IOCTL_SOCKET_CONNECT, &VMRemoteAddr, sizeof(VMRemoteAddr), NULL, 0, Irp, NULL);
    Irp = NULL;

CompleteIrp:
    if (Irp)
        VioWskIrpComplete(pSocket, Irp, Status, 0);

    DEBUG_EXIT_FUNCTION("0x%x", Status);
    return Status;
}


NTSTATUS
WSKAPI
VioWskGetRemoteAddress(
    _In_ PWSK_SOCKET Socket,
    _Out_ PSOCKADDR  RemoteAddress,
    _Inout_ PIRP     Irp
)
{
    PIRP IOCTLIrp = NULL;
    PVIOSOCKET_COMPLETION_CONTEXT CompContext = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVIOWSK_SOCKET pSocket = CONTAINING_RECORD(Socket, VIOWSK_SOCKET, WskSocket);
    DEBUG_ENTER_FUNCTION("Socket=0x%p; RemoteAddress=0x%p; Irp=0x%p", Socket, RemoteAddress, Irp);

    Status = VioWskIrpAcquire(pSocket, Irp);
    if (!NT_SUCCESS(Status))
    {
        pSocket = NULL;
        goto CompleteIrp;
    }

    Status = VioWskSocketBuildIOCTL(pSocket, IOCTL_SOCKET_GET_PEER_NAME, NULL, 0, RemoteAddress, sizeof(SOCKADDR_VM), &IOCTLIrp);
    if (!NT_SUCCESS(Status))
        goto CompleteIrp;

    CompContext = WskCompContextAlloc(wsksReadIOCTL, pSocket, Irp, NULL, NULL);
    if (!CompContext)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto FreeOpIrp;
    }

    Status = CompContextSendIrp(CompContext, IOCTLIrp);
    WskCompContextDereference(CompContext);
    if (NT_SUCCESS(Status))
        IOCTLIrp = NULL;

    Irp = NULL;

FreeOpIrp:
    if (IOCTLIrp)
        IoFreeIrp(IOCTLIrp);
CompleteIrp:
    if (Irp)
        VioWskIrpComplete(pSocket, Irp, Status, 0);

    DEBUG_EXIT_FUNCTION("0x%x", Status);
    return Status;
}

NTSTATUS
WSKAPI
VioWskSend(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF    Buffer,
    _In_ ULONG       Flags,
    _Inout_ PIRP     Irp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVIOWSK_SOCKET pSocket = CONTAINING_RECORD(Socket, VIOWSK_SOCKET, WskSocket);
    DEBUG_ENTER_FUNCTION("Socket=0x%p; Buffer=0x%p; Flags=0x%x; Irp=0x%p", Socket, Buffer, Flags, Irp);

    UNREFERENCED_PARAMETER(Flags);

    Status = VioWskIrpAcquire(pSocket, Irp);
    if (!NT_SUCCESS(Status)) {
        pSocket = NULL;
        goto CompleteIrp;
    }

    Status = VioWskSocketReadWrite(pSocket, Buffer, IRP_MJ_WRITE, Irp);
    Irp = NULL;

CompleteIrp:
    if (Irp)
        VioWskIrpComplete(pSocket, Irp, Status, 0);

    DEBUG_EXIT_FUNCTION("0x%x", Status);
    return Status;
}

NTSTATUS
WSKAPI
VioWskReceive(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF    Buffer,
    _In_ ULONG       Flags,
    _Inout_ PIRP     Irp
)
{
    PVIOWSK_SOCKET pSocket = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    DEBUG_ENTER_FUNCTION("Socket=0x%p; Buffer=0x%p; Flags=0x%x; Irp=0x%p", Socket, Buffer, Flags, Irp);

    if (Flags != 0) {
        Status = STATUS_NOT_SUPPORTED;
        goto CompleteIrp;
    }

    pSocket = CONTAINING_RECORD(Socket, VIOWSK_SOCKET, WskSocket);
    Status = VioWskIrpAcquire(pSocket, Irp);
    if (!NT_SUCCESS(Status)) {
        pSocket = NULL;
        goto CompleteIrp;
    }

    Status = VioWskSocketReadWrite(pSocket, Buffer, IRP_MJ_READ, Irp);
    Irp = NULL;

CompleteIrp:
    if (Irp)
	    VioWskIrpComplete(pSocket, Irp, Status, 0);

    DEBUG_EXIT_FUNCTION("0x%x", Status);
    return Status;
}

NTSTATUS
WSKAPI
VioWskDisconnect(
    _In_ PWSK_SOCKET  Socket,
    _In_opt_ PWSK_BUF Buffer,
    _In_ ULONG        Flags,
    _Inout_ PIRP      Irp
)
{
    PIRP SendIrp = NULL;
    ULONG How = 2; // SD_BOTH
    ULONG firstMdlLength = 0;
    ULONG lastMdlLength = 0;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVIOSOCKET_COMPLETION_CONTEXT CompContext = NULL;
    PVIOWSK_SOCKET pSocket = CONTAINING_RECORD(Socket, VIOWSK_SOCKET, WskSocket);
    DEBUG_ENTER_FUNCTION("Socket=0x%p; Buffer=0x%p; Flags=0x%x; Irp=0x%p", Socket, Buffer, Flags, Irp);

    Status = VioWskIrpAcquire(pSocket, Irp);
    if (!NT_SUCCESS(Status))
    {
        pSocket = NULL;
        goto CompleteIrp;
    }

    if (!Buffer || !Buffer->Mdl || Buffer->Length == 0 || (Flags & WSK_FLAG_ABORTIVE))
    {
        Status = VioWskSocketIOCTL(pSocket, IOCTL_SOCKET_SHUTDOWN, &How, sizeof(How), NULL, 0, Irp, NULL);
        Irp = NULL;
        goto CompleteIrp;
    }

    Status = WskBufferValidate(Buffer, &firstMdlLength, &lastMdlLength);
    if (!NT_SUCCESS(Status))
        goto CompleteIrp;

    Status = VioWskSocketBuildReadWriteSingleMdl(pSocket, Buffer->Mdl, Buffer->Offset, firstMdlLength, IRP_MJ_WRITE, &SendIrp);
    if (!NT_SUCCESS(Status))
        goto CompleteIrp;
 
    CompContext = WskCompContextAlloc(wsksDisconnect, pSocket, Irp, NULL, Buffer->Mdl->Next);
    if (!CompContext) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto FreeSendIrp;
    }

    CompContext->Specific.Transfer.CurrentMdlSize = firstMdlLength;
    CompContext->Specific.Transfer.LastMdlSize = lastMdlLength;
    CompContext->Specific.Transfer.WskBuffer = Buffer;
    Status = CompContextSendIrp(CompContext, SendIrp);
    WskCompContextDereference(CompContext);
    if (NT_SUCCESS(Status))
        SendIrp = NULL;

    Irp = NULL;

FreeSendIrp:
    if (SendIrp)
        IoFreeIrp(SendIrp);
CompleteIrp:
    if (Irp)
        VioWskIrpComplete(pSocket, Irp, Status, 0);

    DEBUG_EXIT_FUNCTION("0x%x", Status);
    return Status;
}

NTSTATUS
WSKAPI
VioWskRelease(
    _In_ PWSK_SOCKET          Socket,
    _In_ PWSK_DATA_INDICATION DataIndication
)
{
    PWSK_DATA_INDICATION Prev = NULL;
    DEBUG_ENTER_FUNCTION("Socket=0x%p; DataIndication=0x%p", Socket, DataIndication);

    UNREFERENCED_PARAMETER(Socket);

    do {
        Prev = DataIndication;
        DataIndication = DataIndication->Next;
        WskFreeMDLs(Prev->Buffer.Mdl);
        ExFreePoolWithTag(Prev, VIOSOCK_WSK_MEMORY_TAG);
    } while (DataIndication != NULL);

    DEBUG_EXIT_FUNCTION("0x%x", STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

NTSTATUS
WSKAPI
VioWskConnectEx(
    _In_ PWSK_SOCKET  Socket,
    _In_ PSOCKADDR    RemoteAddress,
    _In_opt_ PWSK_BUF Buffer,
    _Reserved_ ULONG  Flags,
    _Inout_ PIRP      Irp
)
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(RemoteAddress);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Flags);

    return VioWskCompleteIrp(Irp, STATUS_NOT_IMPLEMENTED, 0);
}

NTSTATUS
WSKAPI
VioWskSendEx(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF    Buffer,
    _In_ ULONG       Flags,
    _In_ ULONG       ControlInfoLength,
    _In_reads_bytes_opt_(ControlInfoLength) PCMSGHDR ControlInfo,
    _Inout_ PIRP     Irp
)
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(ControlInfoLength);
    UNREFERENCED_PARAMETER(ControlInfo);

    return VioWskCompleteIrp(Irp, STATUS_NOT_IMPLEMENTED, 0);
}

NTSTATUS
WSKAPI
VioWskReceiveEx(
    _In_ PWSK_SOCKET   Socket,
    _In_ PWSK_BUF      Buffer,
    _In_ ULONG         Flags,
    _Inout_opt_ PULONG ControlInfoLength,
    _Out_writes_bytes_opt_(*ControlInfoLength) PCMSGHDR ControlInfo,
    _Reserved_ PULONG  ControlFlags,
    _Inout_ PIRP       Irp
)
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(ControlInfoLength);
    UNREFERENCED_PARAMETER(ControlInfo);
    UNREFERENCED_PARAMETER(ControlFlags);

    return VioWskCompleteIrp(Irp, STATUS_NOT_IMPLEMENTED, 0);
}

NTSTATUS
WSKAPI
VioWskListen(
    _In_ PWSK_SOCKET Socket,
    _Inout_ PIRP     Irp
)
{
    UNREFERENCED_PARAMETER(Socket);

    return VioWskCompleteIrp(Irp, STATUS_NOT_IMPLEMENTED, 0);
}
