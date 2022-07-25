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
#include "..\inc\debug-utils.h"
#include "wsk-utils.h"
#include "viowsk-internal.h"
#include "wsk-mdl.h"
#include "wsk-completion.h"


static
NTSTATUS
WskGeneralIrpCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp,
    _In_ PVOID          Context
)
{
    PIRP NextIrp = NULL;
    NTSTATUS NextIrpStatus = STATUS_UNSUCCESSFUL;
    EWSKState opState;
    PVIOSOCKET_COMPLETION_CONTEXT Ctx = (PVIOSOCKET_COMPLETION_CONTEXT)Context;
    DEBUG_ENTER_FUNCTION("DeviceObject=0x%p; Irp=0x%p; Context=0x%p", DeviceObject, Irp, Context);

    UNREFERENCED_PARAMETER(DeviceObject);
    opState = Ctx->State;
    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        switch (opState)
        {
        case wsksReadIOCTL:
            memcpy(Irp->UserBuffer, Irp->AssociatedIrp.SystemBuffer, Irp->IoStatus.Information);
            opState = wsksFinished;
            break;
        case wsksBind:
            if (Ctx->Socket->Type == WSK_FLAG_LISTEN_SOCKET)
            {
                ULONG SendLog = 128;

                Irp->IoStatus.Status = VioWskSocketBuildIOCTL(Ctx->Socket, IOCTL_SOCKET_LISTEN, &SendLog, sizeof(SendLog), NULL, 0, &NextIrp);
                if (!NT_SUCCESS(Irp->IoStatus.Status))
                    break;

                Ctx->State = wsksListen;
                NextIrpStatus = CompContextSendIrp(Ctx, NextIrp);
                if (!NT_SUCCESS(NextIrpStatus))
                {
                    Irp->IoStatus.Status = NextIrpStatus;
                    Ctx->MasterIrp = NULL;
                    IoFreeIrp(NextIrp);
                }
            }
 			else opState = wsksFinished;
			break;
        case wsksAcceptLocal:
            memcpy(Ctx->Specific.Accept.LocalAddress, Irp->AssociatedIrp.SystemBuffer, sizeof(SOCKADDR_VM));
            if (Ctx->Specific.Accept.RemoteAddress)
            {
                Irp->IoStatus.Status = VioWskSocketBuildIOCTL(Ctx->Socket, IOCTL_SOCKET_GET_PEER_NAME, NULL, 0, Ctx->Specific.Accept.RemoteAddress, sizeof(SOCKADDR_VM), &NextIrp);
                if (!NT_SUCCESS(Irp->IoStatus.Status))
                    break;

                Ctx->State = wsksAcceptRemote;
                NextIrpStatus = CompContextSendIrp(Ctx, NextIrp);
                if (!NT_SUCCESS(NextIrpStatus))
                {
					Irp->IoStatus.Status = NextIrpStatus;
                    Ctx->MasterIrp = NULL;
                    IoFreeIrp(NextIrp);
			    }
            }
			else
            {
                opState = wsksFinished;
                WskWorkItemFree(Ctx->Specific.Accept.CloseWorkItem);
                Ctx->Specific.Accept.CloseWorkItem = NULL;
                Ctx->IOSBInformation = (ULONG_PTR)Ctx->Specific.Accept.Socket;
                Ctx->UseIOSBInformation = 1;
            }
            break;
        case wsksAcceptRemote:
            memcpy(Ctx->Specific.Accept.RemoteAddress, Irp->AssociatedIrp.SystemBuffer, sizeof(SOCKADDR_VM));
            opState = wsksFinished;
            WskWorkItemFree(Ctx->Specific.Accept.CloseWorkItem);
            Ctx->Specific.Accept.CloseWorkItem = NULL;
            Ctx->IOSBInformation = (ULONG_PTR)Ctx->Specific.Accept.Socket;
            Ctx->UseIOSBInformation = 1;
            break;
        case wsksListen:
        case wsksDisconnected:
            opState = wsksFinished;
            break;
        case wsksReceive:
            if (Ctx->Mdl &&
                Irp->IoStatus.Information == Ctx->Specific.Transfer.CurrentMdlSize)
            {
                Ctx->Specific.Transfer.CurrentMdlSize = Ctx->Mdl->Next != NULL ? MmGetMdlByteCount(Ctx->Mdl) : Ctx->Specific.Transfer.LastMdlSize;
                Irp->IoStatus.Status = VioWskSocketBuildReadWriteSingleMdl(Ctx->Socket, Ctx->Mdl, 0, Ctx->Specific.Transfer.CurrentMdlSize, IRP_MJ_READ, &NextIrp);
                if (!NT_SUCCESS(Irp->IoStatus.Status))
                    break;

                Ctx->Mdl = Ctx->Mdl->Next;
                NextIrpStatus = CompContextSendIrp(Ctx, NextIrp);
                if (!NT_SUCCESS(NextIrpStatus)) {
                    Irp->IoStatus.Status = NextIrpStatus;
                    Ctx->MasterIrp = NULL;
                    VioWskIrpFree(NextIrp, DeviceObject, FALSE);
                }
			}
            else opState = wsksFinished;

            Ctx->IOSBInformation += Irp->IoStatus.Information;
            Ctx->UseIOSBInformation = 1;
            break;
        case wsksSend:
        case wsksDisconnect:
            if (Ctx->Mdl &&


                (Irp->IoStatus.Information == Ctx->Specific.Transfer.CurrentMdlSize))
             {
                Ctx->Specific.Transfer.CurrentMdlSize = Ctx->Mdl->Next != NULL ? MmGetMdlByteCount(Ctx->Mdl) : Ctx->Specific.Transfer.LastMdlSize;
                 Irp->IoStatus.Status = VioWskSocketBuildReadWriteSingleMdl(Ctx->Socket, Ctx->Mdl, 0, Ctx->Specific.Transfer.CurrentMdlSize, IRP_MJ_WRITE, &NextIrp);
                 if (!NT_SUCCESS(Irp->IoStatus.Status))
                     break;

                Ctx->Mdl = Ctx->Mdl->Next;
                NextIrpStatus = CompContextSendIrp(Ctx, NextIrp);
                if (!NT_SUCCESS(NextIrpStatus)) {
                    Irp->IoStatus.Status = NextIrpStatus;
                    Ctx->MasterIrp = NULL;
                    VioWskIrpFree(NextIrp, DeviceObject, FALSE);
                }
            }
			else if (opState == wsksDisconnect) {
                ULONG How = 2; // SD_BOTH

                Irp->IoStatus.Status = VioWskSocketBuildIOCTL(Ctx->Socket, IOCTL_SOCKET_SHUTDOWN, &How, sizeof(How), NULL, 0, &NextIrp);
               if (!NT_SUCCESS(Irp->IoStatus.Status))
                   break;

                Ctx->State = wsksDisconnected;
                NextIrpStatus = CompContextSendIrp(Ctx, NextIrp);
                if (!NT_SUCCESS(NextIrpStatus)) {
                    Irp->IoStatus.Status = NextIrpStatus;
                    Ctx->MasterIrp = NULL;
                    IoFreeIrp(NextIrp);
                }
			}
            else opState = wsksFinished;

            Ctx->IOSBInformation += Irp->IoStatus.Information;
            Ctx->UseIOSBInformation = 1;
            break;
        default:
            opState = wsksFinished;
            break;
        }
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status) ||
        opState == wsksFinished) {
        if (Ctx->State == wsksAcceptLocal ||
            Ctx->State == wsksAcceptRemote) {
            if (Ctx->Specific.Accept.CloseWorkItem)
            {
                WskWorkItemQueue(Ctx->Specific.Accept.CloseWorkItem);
                Ctx->Specific.Accept.CloseWorkItem = NULL;
            }
        }

        if (Ctx->IoStatusBlock)
            *Ctx->IoStatusBlock = Irp->IoStatus;

        if (Ctx->BytesReturned)
            *Ctx->BytesReturned = Irp->IoStatus.Information;

        if (Ctx->Event)
            KeSetEvent(Ctx->Event, IO_NO_INCREMENT, FALSE);

        if (Ctx->MasterIrp)
        {
            if (!Ctx->UseIOSBInformation)
                Ctx->IOSBInformation = Irp->IoStatus.Information;

            VioWskIrpComplete(Ctx->Socket, Ctx->MasterIrp, Irp->IoStatus.Status, Ctx->IOSBInformation);
        }
    }

    WskCompContextDereference(Ctx);
    VioWskIrpFree(Irp, DeviceObject, TRUE);
    
    DEBUG_EXIT_FUNCTION("0x%x", STATUS_MORE_PROCESSING_REQUIRED);
    return STATUS_MORE_PROCESSING_REQUIRED;
}


PVIOSOCKET_COMPLETION_CONTEXT
WskCompContextAlloc(
	_In_ EWSKState            State,
	_In_ PVIOWSK_SOCKET       Socket,
	_In_opt_ PIRP             MasterIrp,
    _In_opt_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PMDL             Mdl
)
{
    PVIOSOCKET_COMPLETION_CONTEXT Ret = NULL;
    DEBUG_ENTER_FUNCTION("State=%u; Socket=0x%p; MasterIrp=0x%p; IoStatusBlock=0x%p; Mdl=0x%p", State, Socket, MasterIrp, IoStatusBlock, Mdl);

    Ret = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Ret), VIOSOCK_WSK_MEMORY_TAG);
    if (!Ret)
        goto Exit;

    memset(Ret, 0, sizeof(*Ret));
    InterlockedExchange(&Ret->ReferenceCount, 1);
    Ret->State = State;
    Ret->Socket = Socket;
    Ret->MasterIrp = MasterIrp;
    Ret->IoStatusBlock = IoStatusBlock;
    Ret->Mdl = Mdl;

Exit:
    DEBUG_EXIT_FUNCTION("0x%p", Ret);
    return Ret;
}

void
WskCompContextReference(
    _Inout_ PVIOSOCKET_COMPLETION_CONTEXT CompContext
)
{
    DEBUG_ENTER_FUNCTION("CompContext=0x%p", CompContext);

    InterlockedIncrement(&CompContext->ReferenceCount);

    DEBUG_EXIT_FUNCTION_VOID();
    return;
}

void
WskCompContextDereference(
    _Inout_ PVIOSOCKET_COMPLETION_CONTEXT CompContext
)
{
    DEBUG_ENTER_FUNCTION("CompContext=0x%p", CompContext);

    if (InterlockedDecrement(&CompContext->ReferenceCount) == 0)
        ExFreePoolWithTag(CompContext, VIOSOCK_WSK_MEMORY_TAG);

    DEBUG_EXIT_FUNCTION_VOID();
    return;
}


NTSTATUS
CompContextSendIrp(
    _Inout_ PVIOSOCKET_COMPLETION_CONTEXT CompContext,
    _In_ PIRP                             Irp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVIOWSK_REG_CONTEXT pContext = NULL;
    PWSK_REGISTRATION Registration = NULL;
    DEBUG_ENTER_FUNCTION("CompContext=0x%p; Irp=0x%p", CompContext, Irp);

    Status = STATUS_SUCCESS;
    Registration = (PWSK_REGISTRATION)CompContext->Socket->Client;
    pContext = (PVIOWSK_REG_CONTEXT)Registration->ReservedRegistrationContext;
    if (_viowskDeviceObject) {
        Status = IoSetCompletionRoutineEx(_viowskDeviceObject, Irp, WskGeneralIrpCompletion, CompContext, TRUE, TRUE, TRUE);
        if (!NT_SUCCESS(Status))
            goto CompleteMasterIrp;
    } else IoSetCompletionRoutine(Irp, WskGeneralIrpCompletion, CompContext, TRUE, TRUE, TRUE);
   
   WskCompContextReference(CompContext);
    IoCallDriver(pContext->VIOSockDevice, Irp);
    Status = STATUS_PENDING;
    Irp = NULL;
CompleteMasterIrp:
    if (Irp && CompContext->MasterIrp)
        VioWskIrpComplete(CompContext->Socket, CompContext->MasterIrp, Status, 0);

    DEBUG_EXIT_FUNCTION("0x%x", Status);
    return Status;
}
