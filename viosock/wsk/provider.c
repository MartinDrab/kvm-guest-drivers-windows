/*
 * Provider NPI functions
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
#include "viowsk.h"
#include "..\inc\debug-utils.h"
#include "wsk-utils.h"
#include "..\inc\vio_wsk.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, VioWskGetAddressInfo)
#pragma alloc_text (PAGE, VioWskFreeAddressInfo)
#pragma alloc_text (PAGE, VioWskGetNameInfo)
#endif

static
NTSTATUS
VioWskSocketInternal(
    _In_ PWSK_CLIENT              Client,
    _In_ ULONG                    Flags,
    _In_opt_ PVOID                SocketContext,
    _In_opt_ CONST VOID          *Dispatch,
    _In_opt_ PEPROCESS            OwningProcess,
    _In_opt_ PETHREAD             OwningThread,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Out_ PVIOWSK_SOCKET         *pNewSocket,
    _Out_ PBOOLEAN                CompleteIrp
)
{
    PWSK_CLIENT_LISTEN_DISPATCH pListenDispatch = NULL;
    PWSK_CLIENT_CONNECTION_DISPATCH pConnectionDispatch = NULL;
    PVIOWSK_SOCKET pSocket;
    NTSTATUS Status;
    PVOID pProviderDispatch;
    SIZE_T ProviderDispatchSize;

    UNREFERENCED_PARAMETER(Client);
    UNREFERENCED_PARAMETER(OwningProcess);
    UNREFERENCED_PARAMETER(OwningThread);
    UNREFERENCED_PARAMETER(SecurityDescriptor);

    ASSERT(pNewSocket&&CompleteIrp);

    *pNewSocket = NULL;
    *CompleteIrp = FALSE;

    switch (Flags)
    {
    case WSK_FLAG_BASIC_SOCKET:
        pProviderDispatch = &gBasicDispatch;
        ProviderDispatchSize = sizeof(gBasicDispatch);
        break;
    case WSK_FLAG_LISTEN_SOCKET:
        pListenDispatch = (PWSK_CLIENT_LISTEN_DISPATCH)Dispatch;
        pProviderDispatch = &gListenDispatch;
        ProviderDispatchSize = sizeof(gListenDispatch);
        break;
    case WSK_FLAG_CONNECTION_SOCKET:
        pConnectionDispatch = (PWSK_CLIENT_CONNECTION_DISPATCH)Dispatch;
        pProviderDispatch = &gConnectionDispatch;
        ProviderDispatchSize = sizeof(gConnectionDispatch);
        break;
    case WSK_FLAG_DATAGRAM_SOCKET:
        *CompleteIrp = TRUE;
        return STATUS_NOT_SUPPORTED;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    case WSK_FLAG_STREAM_SOCKET:
        if (Dispatch)
        {
            pListenDispatch = (PWSK_CLIENT_LISTEN_DISPATCH)((PWSK_CLIENT_STREAM_DISPATCH)Dispatch)->Listen;
            pConnectionDispatch = (PWSK_CLIENT_CONNECTION_DISPATCH)((PWSK_CLIENT_STREAM_DISPATCH)Dispatch)->Connect;
        }
        pProviderDispatch = &gStreamDispatch;
        ProviderDispatchSize = sizeof(gStreamDispatch);
        break;
#endif // if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    default:
        return STATUS_INVALID_PARAMETER;
    }

    *CompleteIrp = TRUE;

    pSocket = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(VIOWSK_SOCKET), VIOSOCK_WSK_MEMORY_TAG);
    if (pSocket)
    {
        pSocket->SocketContext = SocketContext;
        pSocket->Type = Flags;

        if (pListenDispatch)
            RtlCopyMemory(&pSocket->ListenDispatch, pListenDispatch, sizeof(*pListenDispatch));

        if (pConnectionDispatch)
            RtlCopyMemory(&pSocket->ConnectionDispatch, pConnectionDispatch, sizeof(*pConnectionDispatch));

        RtlCopyMemory(&pSocket->ProviderDispatch, pProviderDispatch, ProviderDispatchSize);
        pSocket->WskSocket.Dispatch = &pSocket->ProviderDispatch;

        //TODO: Open socket
        *pNewSocket = pSocket;
        Status = STATUS_SUCCESS;
    }
    else
        Status = STATUS_INSUFFICIENT_RESOURCES;

    return Status;
}

NTSTATUS
WSKAPI
VioWskSocket(
    _In_ PWSK_CLIENT              Client,
    _In_ ADDRESS_FAMILY           AddressFamily,
    _In_ USHORT                   SocketType,
    _In_ ULONG                    Protocol,
    _In_ ULONG                    Flags,
    _In_opt_ PVOID                SocketContext,
    _In_opt_ CONST VOID          *Dispatch,
    _In_opt_ PEPROCESS            OwningProcess,
    _In_opt_ PETHREAD             OwningThread,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Inout_ PIRP                  Irp
    )
{
    PVIOWSK_SOCKET pSocket;
    NTSTATUS Status;
    BOOLEAN CompleteIrp;

    if (!Client || !Irp)
        return STATUS_INVALID_PARAMETER;

    if (AddressFamily != AF_VSOCK || SocketType != SOCK_STREAM || Protocol != 0)
        return VioWskCompleteIrp(Irp, STATUS_NOT_SUPPORTED, 0);

    Status = VioWskSocketInternal(Client, Flags, SocketContext, Dispatch, OwningProcess,
        OwningThread, SecurityDescriptor, &pSocket, &CompleteIrp);

    if (CompleteIrp)
        VioWskCompleteIrp(Irp, Status, (ULONG_PTR)pSocket);

    return Status;
}

NTSTATUS
WSKAPI
VioWskSocketConnect(
    _In_ PWSK_CLIENT                               Client,
    _In_ USHORT                                    SocketType,
    _In_ ULONG                                     Protocol,
    _In_ PSOCKADDR                                 LocalAddress,
    _In_ PSOCKADDR                                 RemoteAddress,
    _Reserved_ ULONG                               Flags,
    _In_opt_ PVOID                                 SocketContext,
    _In_opt_ CONST WSK_CLIENT_CONNECTION_DISPATCH *Dispatch,
    _In_opt_ PEPROCESS                             OwningProcess,
    _In_opt_ PETHREAD                              OwningThread,
    _In_opt_ PSECURITY_DESCRIPTOR                  SecurityDescriptor,
    _Inout_ PIRP                                   Irp
)
{
    PVIOWSK_SOCKET pSocket;
    NTSTATUS Status;
    BOOLEAN CompleteIrp;

    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(RemoteAddress);
    UNREFERENCED_PARAMETER(Flags);

    if (!Client || !Irp)
        return STATUS_INVALID_PARAMETER;

    if (SocketType != SOCK_STREAM || Protocol != 0)
        return VioWskCompleteIrp(Irp, STATUS_NOT_SUPPORTED, 0);

    Status = VioWskSocketInternal(Client, WSK_FLAG_CONNECTION_SOCKET, SocketContext,
        Dispatch, OwningProcess, OwningThread, SecurityDescriptor, &pSocket, &CompleteIrp);

    if (NT_SUCCESS(Status))
    {
        //TODO: bind and connect
    }

    if (CompleteIrp)
        VioWskCompleteIrp(Irp, Status, (ULONG_PTR)pSocket);

    return Status;
}

NTSTATUS
WSKAPI
VioWskControlClient(
    _In_ PWSK_CLIENT                    Client,
    _In_ ULONG                          ControlCode,
    _In_ SIZE_T                         InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID    InputBuffer,
    _In_ SIZE_T                         OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID  OutputBuffer,
    _Out_opt_ SIZE_T                   *OutputSizeReturned,
    _Inout_opt_ PIRP                    Irp
)
{
    UNREFERENCED_PARAMETER(Client);
    UNREFERENCED_PARAMETER(ControlCode);
    UNREFERENCED_PARAMETER(InputSize);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(OutputSize);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputSizeReturned);

    return VioWskCompleteIrp(Irp, STATUS_NOT_IMPLEMENTED, 0);
}

_At_(*Result, __drv_allocatesMem(Mem))
NTSTATUS
WSKAPI
VioWskGetAddressInfo(
    _In_ PWSK_CLIENT          Client,
    _In_opt_ PUNICODE_STRING  NodeName,
    _In_opt_ PUNICODE_STRING  ServiceName,
    _In_opt_ ULONG            NameSpace,
    _In_opt_ GUID            *Provider,
    _In_opt_ PADDRINFOEXW     Hints,
    _Outptr_ PADDRINFOEXW    *Result,
    _In_opt_ PEPROCESS        OwningProcess,
    _In_opt_ PETHREAD         OwningThread,
    _Inout_ PIRP              Irp
)
{
    ULONG Cid = 0;
    ULONG Port = 0;
    ULONG_PTR SizeReturned = 0;
    PADDRINFOEXW AddrInfo = NULL;
    PSOCKADDR_VM VMAddr = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    DEBUG_ENTER_FUNCTION("Client=0x%p; NodeName=\"%wZ\"; ServiceName=\"%wZ\"; NameSpace=%u; Provider=0x%p; Hints=0x%p; Result=0x%p; OwningProcess=0x%p; OwningThread=0x%p; Irp=0x%p", Client, NodeName, ServiceName, NameSpace, Provider, Hints, Result, OwningProcess, OwningThread, Irp);

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Client);
    UNREFERENCED_PARAMETER(NameSpace);
    UNREFERENCED_PARAMETER(Provider);
    UNREFERENCED_PARAMETER(Hints);
    UNREFERENCED_PARAMETER(OwningProcess);
    UNREFERENCED_PARAMETER(OwningThread);

    Status = STATUS_SUCCESS;
    IoSetNextIrpStackLocation(Irp);
    if (NodeName)
    {
        Status = VioWskStringToAddressPart(NodeName, &Cid);
        if (!NT_SUCCESS(Status))
            goto CompleteIrp;
    }

    if (ServiceName)
    {
        Status = VioWskStringToAddressPart(ServiceName, &Port);
        if (!NT_SUCCESS(Status))
            goto CompleteIrp;
    }

    VMAddr = ExAllocatePoolWithTag(NonPagedPool, sizeof(SOCKADDR_VM), VIOSOCK_WSK_MEMORY_TAG);
    if (!VMAddr)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto CompleteIrp;
    }

    memset(VMAddr, 0, sizeof(SOCKADDR_VM));
    VMAddr->svm_family = AF_VSOCK;
    VMAddr->svm_cid = Cid;
    VMAddr->svm_port = Port;
    AddrInfo = ExAllocatePoolWithTag(PagedPool, sizeof(ADDRINFOEXW), VIOSOCK_WSK_MEMORY_TAG);
    if (!AddrInfo)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto FreeVMAddr;
	}

    memset(AddrInfo, 0, sizeof(ADDRINFOEXW));
    AddrInfo->ai_family = AF_VSOCK;
    AddrInfo->ai_socktype = SOCK_STREAM;
    AddrInfo->ai_addr = (struct sockaddr*)VMAddr;
    AddrInfo->ai_addrlen = sizeof(SOCKADDR_VM);
    *Result = AddrInfo;
    SizeReturned = sizeof(ADDRINFOEXW);
    VMAddr = NULL;

FreeVMAddr:
    if (VMAddr)
        ExFreePoolWithTag(VMAddr, VIOSOCK_WSK_MEMORY_TAG);
CompleteIrp:
    if (Irp)
        VioWskIrpComplete(NULL, Irp, Status, SizeReturned);

    DEBUG_EXIT_FUNCTION("0x%x, *Result=0x%p", Status, *Result);
    return Status;
}

_At_(AddrInfo, __drv_freesMem(Mem))
VOID
WSKAPI
VioWskFreeAddressInfo(
    _In_ PWSK_CLIENT  Client,
    _In_ PADDRINFOEXW AddrInfo
    )
{

    PADDRINFOEXW Prev = NULL;
    DEBUG_ENTER_FUNCTION("Client=0x%p; AddrInfo=0x%p", Client, AddrInfo);

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Client);

    while (AddrInfo != NULL)
    {
        Prev = AddrInfo;
        AddrInfo = AddrInfo->ai_next;
        ExFreePoolWithTag(Prev->ai_addr, VIOSOCK_WSK_MEMORY_TAG);
        ExFreePoolWithTag(Prev, VIOSOCK_WSK_MEMORY_TAG);
    }

    DEBUG_EXIT_FUNCTION_VOID();
    return;
}

NTSTATUS
WSKAPI
VioWskGetNameInfo(
    _In_ PWSK_CLIENT          Client,
    _In_ PSOCKADDR            SockAddr,
    _In_ ULONG                SockAddrLength,
    _Out_opt_ PUNICODE_STRING NodeName,
    _Out_opt_ PUNICODE_STRING ServiceName,
    _In_ ULONG                Flags,
    _In_opt_ PEPROCESS        OwningProcess,
    _In_opt_ PETHREAD         OwningThread,
    _Inout_ PIRP              Irp
)
{
    PSOCKADDR_VM VMAddr = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    DEBUG_ENTER_FUNCTION("Client=0x%p; SockAddr=0x%p; SockAddrLength=%u; NodeName=0x%p; ServiceName=0x%p; Flags=0x%x; OwningProcess=0x%p; OwningThread=0x%p; Irp=0x%p", Client, SockAddr, SockAddrLength, NodeName, ServiceName, Flags, OwningProcess, OwningThread, Irp);

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Client);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(OwningProcess);
    UNREFERENCED_PARAMETER(OwningThread);

    Status = STATUS_SUCCESS;
    IoSetNextIrpStackLocation(Irp);
    VMAddr = (PSOCKADDR_VM)SockAddr;
    if ((NodeName == NULL && ServiceName == NULL) ||
        SockAddrLength != sizeof(SOCKADDR_VM) ||
        VMAddr->svm_family != AF_VSOCK) {
        Status = STATUS_INVALID_PARAMETER;
        goto CompleteIrp;
    }

    if (NodeName != NULL) {
        Status = VioWskAddressPartToString(VMAddr->svm_cid, NodeName);
        if (!NT_SUCCESS(Status))
            goto CompleteIrp;
    }

    if (ServiceName != NULL) {
        Status = VioWskAddressPartToString(VMAddr->svm_port, ServiceName);
        if (!NT_SUCCESS(Status))
            goto CompleteIrp;
    }

CompleteIrp:
    if (Irp)
        Status = VioWskIrpComplete(NULL, Irp, Status, 0);

    DEBUG_EXIT_FUNCTION("0x%x, Nodename=\"%wZ\", Servicename=\"%wZ\"", Status, NodeName, ServiceName);
    return Status;
}
