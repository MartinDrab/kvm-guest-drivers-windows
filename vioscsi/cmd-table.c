/*
 * This file contains vioscsi StorPort miniport driver
 *
 * Copyright (c) 2012-2017 Red Hat, Inc.
 *
 * Author(s):
 *  Vadim Rozenfeld <vrozenfe@redhat.com>
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

#include <ntddk.h>
#include <storport.h>
#include "helper.h"
#include "vioscsi.h"
#include "trace.h"
#include "cmd-table.h"

#if defined(EVENT_TRACING)
#include "cmd-table.tmh"
#endif


#define CMD_TABLE_TAG					(ULONG)'EDMC'

typedef struct _CMD_ITEM {
    VirtIOSCSICmd Cmd;
    SLIST_ENTRY Entry;
    volatile LONG ReferenceCount;
} CMD_ITEM, *PCMD_ITEM;

static volatile LONG _cmdCacheSize;
static volatile LONG _entryCacheSize;
static volatile LONG _cmdCount;
static volatile LONG _entryCount;


static inline size_t _HashFunction(const CMD_TABLE *Table, PVOID Cmd)
{
    return (ULONG_PTR)Cmd % (sizeof(Table->Entries) / sizeof(Table->Entries[0]));
}


static void _LockBucket(PCMD_TABLE Table, size_t Index)
{
    while (InterlockedCompareExchange(Table->Lock + Index, 1, 0))
        __nop();

    return;
}


static void _UnlockBucket(PCMD_TABLE Table, size_t Index)
{
    InterlockedExchange(Table->Lock + Index, 0);

    return;
}


static void _CmdItemReference(PCMD_TABLE Table, PCMD_ITEM Item)
{
    InterlockedIncrement(&Item->ReferenceCount);

    return;
}


static void _CmdItemDereference(PCMD_TABLE Table, PCMD_ITEM Item)
{
    if (InterlockedDecrement(&Item->ReferenceCount) == 0) {
        InterlockedPushEntrySList(&Table->FreeCmds, &Item->Entry);
        InterlockedIncrement(&_cmdCacheSize);
        InterlockedDecrement(&_cmdCount);
    }

    return;
}


void CmdTableInit(PCMD_TABLE Table, PVOID DeviceExtension)
{
    InitializeSListHead(&Table->Cache);
    InitializeSListHead(&Table->FreeCmds);
    Table->DeviceExtension = DeviceExtension;
    for (size_t i = 0; i < sizeof(Table->Entries)/sizeof(Table->Entries[0]); ++i) {
        InterlockedExchange(Table->Lock + i, 0);
        Table->Entries[i] = NULL;
    }

    return;
}


void CmdTableFinit(PCMD_TABLE Table)
{
    PCMD_ITEM item = NULL;
    PSLIST_ENTRY sle = NULL;
    PCMD_TABLE_ENTRY cte = NULL;
    PCMD_TABLE_ENTRY old = NULL;

    for (size_t i = 0; i < sizeof(Table->Entries) / sizeof(Table->Entries[0]); ++i) {
        cte = Table->Entries[i];
        while (cte != NULL) {
            old = cte;
            cte = cte->Next;
            StorPortFreePool(Table->DeviceExtension, old->Cmd);
            StorPortFreePool(Table->DeviceExtension, old);
            InterlockedDecrement(&_cmdCount);
            InterlockedDecrement(&_entryCount);
        }

        Table->Entries[i] = NULL;
    }

    while (sle = InterlockedPopEntrySList(&Table->Cache)) {
        cte = CONTAINING_RECORD(sle, CMD_TABLE_ENTRY, CacheEntry);
        StorPortFreePool(Table->DeviceExtension, cte);
        InterlockedDecrement(&_entryCacheSize);
    }

    while (sle = InterlockedPopEntrySList(&Table->FreeCmds)) {
        item = CONTAINING_RECORD(sle, CMD_ITEM, Entry);
        StorPortFreePool(Table->DeviceExtension, item);
        InterlockedDecrement(&_cmdCacheSize);
    }

    return;
}


ULONG CmdTableAllocItem(PCMD_TABLE Table, PVOID *Cmd)
{
    PCMD_ITEM tmpCmd = NULL;
    PSLIST_ENTRY sle = NULL;
    ULONG ret = STOR_STATUS_SUCCESS;

    sle = InterlockedPopEntrySList(&Table->FreeCmds);
    if (sle != NULL) {
        InterlockedDecrement(&_cmdCacheSize);
        tmpCmd = CONTAINING_RECORD(sle, CMD_ITEM, Entry);
        ret = STOR_STATUS_SUCCESS;
    } else ret = StorPortAllocatePool(Table->DeviceExtension, sizeof(CMD_ITEM), 0, &tmpCmd);

    if (ret == STOR_STATUS_SUCCESS) {
        InterlockedIncrement(&_cmdCount);
        RtlZeroMemory(tmpCmd, sizeof(CMD_ITEM));
        InterlockedExchange(&tmpCmd->ReferenceCount, 1);
        *Cmd = tmpCmd;
    }

    return ret;
}


void CmdTableClearSrb(PCMD_TABLE Table, PVOID Cmd)
{
    PCMD_ITEM item = NULL;

    item = (PCMD_ITEM)Cmd;
    InterlockedExchangePointer(&item->Cmd.srb, NULL);

    return;
}


void CmdTableDereferenceItem(PCMD_TABLE Table, PVOID Cmd)
{
    PCMD_ITEM item = NULL;

    item = (PCMD_ITEM)Cmd;
    _CmdItemDereference(Table, item);

    return;
}


ULONG CmdTableInsert(PCMD_TABLE Table, PVOID Cmd)
{
    size_t index = 0;
    PCMD_ITEM cmdItem = NULL;
    PCMD_TABLE_ENTRY entry = NULL;
    PSLIST_ENTRY cacheEntry = NULL;
    ULONG ret = STOR_STATUS_SUCCESS;

    cacheEntry = InterlockedPopEntrySList(&Table->Cache);
    if (cacheEntry != NULL) {
        entry = CONTAINING_RECORD(cacheEntry, CMD_TABLE_ENTRY, CacheEntry);
        InterlockedDecrement(&_entryCacheSize);
        ret = STOR_STATUS_SUCCESS;
    } else ret = StorPortAllocatePool(Table->DeviceExtension, sizeof(CMD_TABLE_ENTRY), CMD_TABLE_TAG, &entry);
	
    if (ret == STOR_STATUS_SUCCESS) {
        InterlockedIncrement(&_entryCount);
        RtlZeroMemory(entry, sizeof(CMD_TABLE_ENTRY));
        entry->Cmd = Cmd;
        cmdItem = (PCMD_ITEM)entry->Cmd;
        _CmdItemReference(Table, cmdItem);
        index = _HashFunction(Table, entry->Cmd);
        _LockBucket(Table, index);
        entry->Next = Table->Entries[index];
        Table->Entries[index] = entry;
        _UnlockBucket(Table, index);
    }

    return ret;
}


BOOLEAN CmdTableDelete(PCMD_TABLE Table, PVOID Cmd)
{
    size_t index = 0;
    BOOLEAN ret = FALSE;
    PCMD_ITEM item = NULL;
    PCMD_TABLE_ENTRY prev = NULL;
    PCMD_TABLE_ENTRY entry = NULL;

    index = _HashFunction(Table, Cmd);
    _LockBucket(Table, index);
    entry = Table->Entries[index];
    while (entry != NULL) {
        if (entry->Cmd == Cmd) {
            ret = TRUE;
            if (prev != NULL)
                prev->Next = entry->Next;
            else Table->Entries[index] = entry->Next;

            break;
        }

        prev = entry;
        entry = entry->Next;
    }

    _UnlockBucket(Table, index);
    if (ret) {
        item = (PCMD_ITEM)entry->Cmd;
        InterlockedPushEntrySList(&Table->Cache, &entry->CacheEntry);
        InterlockedIncrement(&_entryCacheSize);
        InterlockedDecrement(&_entryCount);
    }

    return ret;
}
