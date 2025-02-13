
#ifndef __VIOSTOR_VBR_TABLE_H__
#define __VIOSTOR_VBR_TABLE_H__

#include <ntddk.h>
#include <storport.h>

#define VBR_TABLE_ENTRIES           37

typedef struct _VBR_TABLE_ENTRY {
    PVOID Vbr;
    union {
        struct _VBR_TABLE_ENTRY *Next;
        SLIST_ENTRY CacheEntry;
    };
} VBR_TABLE_ENTRY, *PVBR_TABLE_ENTRY;

typedef struct _VBR_TABLE {
    SLIST_HEADER Cache;
    SLIST_HEADER FreeVbrs;
    PVOID DeviceExtension;
    PVBR_TABLE_ENTRY Entries[VBR_TABLE_ENTRIES];
    volatile LONG Lock[VBR_TABLE_ENTRIES];
} VBR_TABLE, *PVBR_TABLE;



void VbrTableInit(PVBR_TABLE Table, PVOID DeviceExtension);
void VbrTableFinit(PVBR_TABLE Table);
ULONG VbrTableAllocItem(PVBR_TABLE Table, PVOID *Vbr);
void VbrTableClearSrb(PVBR_TABLE Table, PVOID Vbr);
void VbrTableDereferenceItem(PVBR_TABLE Table, PVOID Vbr);
ULONG VbrTableInsert(PVBR_TABLE Table, PVOID Vbr);
BOOLEAN VbrTableDelete(PVBR_TABLE Table, PVOID Vbr);
BOOLEAN VbrTableExists(PVBR_TABLE Table, PVOID Vbr);


#endif
