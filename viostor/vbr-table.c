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
#include "virtio_stor.h"
#include "vbr-table.h"


#define VBR_TABLE_TAG					(ULONG)'ERBV'

typedef struct _VBR_ITEM {
    blk_req Vbr;
    SLIST_ENTRY Entry;
    volatile LONG ReferenceCount;
} VBR_ITEM, *PVBR_ITEM;

static volatile LONG _vbrCacheSize;
static volatile LONG _entryCacheSize;
static volatile LONG _vbrCount;
static volatile LONG _entryCount;


static size_t _HashFunction(const VBR_TABLE *Table, PVOID Vbr)
{
    return (ULONG_PTR)Vbr % (sizeof(Table->Entries) / sizeof(Table->Entries[0]));
}


static void _LockBucket(PVBR_TABLE Table, size_t Index)
{
    while (InterlockedCompareExchange(Table->Lock + Index, 1, 0))
        __nop();

    return;
}


static void _UnlockBucket(PVBR_TABLE Table, size_t Index)
{
    InterlockedExchange(Table->Lock + Index, 0);

    return;
}


static void _VbrItemReference(PVBR_TABLE Table, PVBR_ITEM Item)
{
    InterlockedIncrement(&Item->ReferenceCount);

    return;
}


static void _VbrItemDereference(PVBR_TABLE Table, PVBR_ITEM Item)
{
    if (InterlockedDecrement(&Item->ReferenceCount) == 0) {
        InterlockedPushEntrySList(&Table->FreeVbrs, &Item->Entry);
        InterlockedIncrement(&_vbrCacheSize);
        InterlockedDecrement(&_vbrCount);
    }

    return;
}


void VbrTableInit(PVBR_TABLE Table, PVOID DeviceExtension)
{
    InitializeSListHead(&Table->Cache);
    InitializeSListHead(&Table->FreeVbrs);
    Table->DeviceExtension = DeviceExtension;
    for (size_t i = 0; i < sizeof(Table->Entries)/sizeof(Table->Entries[0]); ++i) {
        InterlockedExchange(Table->Lock + i, 0);
        Table->Entries[i] = NULL;
    }

    return;
}


void VbrTableFinit(PVBR_TABLE Table)
{
    PVBR_ITEM item = NULL;
    PSLIST_ENTRY sle = NULL;
    PVBR_TABLE_ENTRY cte = NULL;
    PVBR_TABLE_ENTRY old = NULL;

    for (size_t i = 0; i < sizeof(Table->Entries) / sizeof(Table->Entries[0]); ++i) {
        cte = Table->Entries[i];
        while (cte != NULL) {
            old = cte;
            cte = cte->Next;
            StorPortFreePool(Table->DeviceExtension, old->Vbr);
            StorPortFreePool(Table->DeviceExtension, old);
            InterlockedDecrement(&_vbrCount);
            InterlockedDecrement(&_entryCount);
        }

        Table->Entries[i] = NULL;
    }

    while (sle = InterlockedPopEntrySList(&Table->Cache)) {
        cte = CONTAINING_RECORD(sle, VBR_TABLE_ENTRY, CacheEntry);
        StorPortFreePool(Table->DeviceExtension, cte);
        InterlockedDecrement(&_entryCacheSize);
    }

    while (sle = InterlockedPopEntrySList(&Table->FreeVbrs)) {
        item = CONTAINING_RECORD(sle, VBR_ITEM, Entry);
        StorPortFreePool(Table->DeviceExtension, item);
        InterlockedDecrement(&_vbrCacheSize);
    }

    return;
}


ULONG VbrTableAllocItem(PVBR_TABLE Table, PVOID *Vbr)
{
    PVBR_ITEM tmpVbr = NULL;
    PSLIST_ENTRY sle = NULL;
    ULONG ret = STOR_STATUS_SUCCESS;

    sle = InterlockedPopEntrySList(&Table->FreeVbrs);
    if (sle != NULL) {
        InterlockedDecrement(&_vbrCacheSize);
        tmpVbr = CONTAINING_RECORD(sle, VBR_ITEM, Entry);
        ret = STOR_STATUS_SUCCESS;
    } else ret = StorPortAllocatePool(Table->DeviceExtension, sizeof(VBR_ITEM), 0, &tmpVbr);

    if (ret == STOR_STATUS_SUCCESS) {
        InterlockedIncrement(&_vbrCount);
        RtlZeroMemory(tmpVbr, sizeof(VBR_ITEM));
        InterlockedExchange(&tmpVbr->ReferenceCount, 1);
        *Vbr = tmpVbr;
    }

    return ret;
}


void VbrTableClearSrb(PVBR_TABLE Table, PVOID Vbr)
{
    PVBR_ITEM item = NULL;

    item = (PVBR_ITEM)Vbr;
    InterlockedExchangePointer(&item->Vbr.req, NULL);

    return;
}


void VbrTableDereferenceItem(PVBR_TABLE Table, PVOID Vbr)
{
    PVBR_ITEM item = NULL;

    item = (PVBR_ITEM)Vbr;
    _VbrItemDereference(Table, item);

    return;
}


ULONG VbrTableInsert(PVBR_TABLE Table, PVOID Vbr)
{
    size_t index = 0;
    PVBR_ITEM vbrItem = NULL;
    PVBR_TABLE_ENTRY entry = NULL;
    PSLIST_ENTRY cacheEntry = NULL;
    ULONG ret = STOR_STATUS_SUCCESS;

    cacheEntry = InterlockedPopEntrySList(&Table->Cache);
    if (cacheEntry != NULL) {
        entry = CONTAINING_RECORD(cacheEntry, VBR_TABLE_ENTRY, CacheEntry);
        InterlockedDecrement(&_entryCacheSize);
        ret = STOR_STATUS_SUCCESS;
    } else ret = StorPortAllocatePool(Table->DeviceExtension, sizeof(VBR_TABLE_ENTRY), VBR_TABLE_TAG, &entry);
	
    if (ret == STOR_STATUS_SUCCESS) {
        InterlockedIncrement(&_entryCount);
        RtlZeroMemory(entry, sizeof(VBR_TABLE_ENTRY));
        entry->Vbr = Vbr;
        vbrItem = (PVBR_ITEM)entry->Vbr;
        _VbrItemReference(Table, vbrItem);
        index = _HashFunction(Table, entry->Vbr);
        _LockBucket(Table, index);
        entry->Next = Table->Entries[index];
        Table->Entries[index] = entry;
        _UnlockBucket(Table, index);
    }

    return ret;
}


BOOLEAN VbrTableDelete(PVBR_TABLE Table, PVOID Vbr)
{
    size_t index = 0;
    BOOLEAN ret = FALSE;
    PVBR_ITEM item = NULL;
    PVBR_TABLE_ENTRY prev = NULL;
    PVBR_TABLE_ENTRY entry = NULL;

    index = _HashFunction(Table, Vbr);
    _LockBucket(Table, index);
    entry = Table->Entries[index];
    while (entry != NULL) {
        if (entry->Vbr == Vbr) {
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
        item = (PVBR_ITEM)entry->Vbr;
        InterlockedPushEntrySList(&Table->Cache, &entry->CacheEntry);
        InterlockedIncrement(&_entryCacheSize);
        InterlockedDecrement(&_entryCount);
    }

    return ret;
}


BOOLEAN VbrTableExists(PVBR_TABLE Table, PVOID Vbr)
{
    size_t index = 0;
    BOOLEAN ret = FALSE;
    PVBR_ITEM item = NULL;
    PVBR_TABLE_ENTRY entry = NULL;

    index = _HashFunction(Table, Vbr);
    _LockBucket(Table, index);
    entry = Table->Entries[index];
    while (entry != NULL) {
        if (entry->Vbr == Vbr) {
            ret = TRUE; 
            break;
        }

        entry = entry->Next;
    }

    _UnlockBucket(Table, index);

    return ret;
}
