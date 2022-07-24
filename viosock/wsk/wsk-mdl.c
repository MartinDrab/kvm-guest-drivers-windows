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
#include "wsk-mdl.h"



_Must_inspect_result_
NTSTATUS
WskBufToMDLs(
    _In_ const WSK_BUF* WskBuf,
    _In_ LOCK_OPERATION Operation,
    _Out_ PMDL         *MDLList
)
{
    PMDL FirstMdl = NULL;
    PMDL PrevMdl = NULL;
    ULONG Offset = WskBuf->Offset;
    SIZE_T Length = WskBuf->Length;
    PMDL SourceMdl = WskBuf->Mdl;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    DEBUG_ENTER_FUNCTION("WskBuf=0x%p; Operation=%u; MDLList=0x%p", WskBuf, Operation, MDLList);

    Status = STATUS_SUCCESS;
    while (Length > 0 && SourceMdl != NULL)
    {
        SIZE_T SourceSize = 0;
        PMDL TargetMdl = NULL;
        PVOID SourceAddress = NULL;

        SourceSize = MmGetMdlByteCount(SourceMdl) - Offset;
        if (SourceSize > Length)
            SourceSize = Length;

        SourceAddress = MmGetSystemAddressForMdlSafe(SourceMdl, NormalPagePriority);
        if (!SourceAddress)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        TargetMdl = IoAllocateMdl((unsigned char*)SourceAddress + Offset, (ULONG)SourceSize, FALSE, FALSE, NULL);
        if (!TargetMdl)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        __try
        {
            MmProbeAndLockPages(TargetMdl, KernelMode, Operation);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
            IoFreeMdl(TargetMdl);
            break;
        }

        if (FirstMdl == NULL)
            FirstMdl = TargetMdl;
        else PrevMdl->Next = TargetMdl;

        PrevMdl = TargetMdl;
        Length -= (ULONG)SourceSize;
        SourceMdl = SourceMdl->Next;
        Offset = 0;
    }

    if (!NT_SUCCESS(Status))
        goto FreeMdlList;

    if (Length > 0)
        Status = STATUS_BUFFER_OVERFLOW;

    if (NT_SUCCESS(Status))
    {
        *MDLList = FirstMdl;
        FirstMdl = NULL;
    }

FreeMdlList:
    if (FirstMdl)
        WskFreeMDLs(FirstMdl);

    DEBUG_EXIT_FUNCTION("0x%x, *MDLList=0x%p", Status, *MDLList);
    return Status;
}


void
WskFreeMDLs(
    _Inout_opt_ PMDL MDLList
)
{
    PMDL NextMdl = NULL;
    DEBUG_ENTER_FUNCTION("MDLList=0x%p", MDLList);

    if (MDLList) {
        do {
            NextMdl = MDLList->Next;
            MmUnlockPages(MDLList);
            IoFreeMdl(MDLList);
            MDLList = NextMdl;
        } while (NextMdl != NULL);
    }

    DEBUG_EXIT_FUNCTION_VOID();
    return;
}


NTSTATUS
WskBufferValidate(
    _In_ const WSK_BUF *Buffer,
    _Out_ PULONG FirstMdlLength,
    _Out_ PULONG LastMdlLength
)
{
    PMDL mdl = NULL;
    ULONG offset = 0;
    SIZE_T length = 0;
    ULONG mdlLength = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DEBUG_ENTER_FUNCTION("Buffer=0x%p; FirstMdlLength=0x%p; LastMdlLength=0x%p", Buffer, FirstMdlLength, LastMdlLength);

    *FirstMdlLength = 0;
    *LastMdlLength = 0;
    status = STATUS_SUCCESS;
    length = Buffer->Length;
    offset = Buffer->Offset;
    mdl = Buffer->Mdl;
    if (mdl != NULL)
    {
        mdlLength = MmGetMdlByteCount(mdl);
        if (offset <= mdlLength)
        {
            while (TRUE)
            {
                ULONG effectiveLength = mdlLength - offset;

                if (length < effectiveLength)
                    effectiveLength = (ULONG)length;

                if (mdl == Buffer->Mdl)
                    *FirstMdlLength = effectiveLength;
                    
                mdl = mdl->Next;
                length -= effectiveLength;
                if (length == 0 || mdl == NULL)
                {
                    *LastMdlLength = effectiveLength;
                    break;
                }

                mdlLength = MmGetMdlByteCount(mdl);
                offset = 0;
            }
        }
        else status = STATUS_INVALID_PARAMETER;
    }
    else if (length != 0)
        status = STATUS_INVALID_PARAMETER;

    DEBUG_EXIT_FUNCTION("0x%x, *FirstMdlLength=%u, *LastMdlLength=%u", status, *FirstMdlLength, *LastMdlLength);
    return status;
}
