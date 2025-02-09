
#ifndef __VIOSCSI_SRB_TABLE_H__
#define __VIOSCSI_SRB_TABLE_H__

#include <ntddk.h>
#include <storport.h>

#define CMD_TABLE_ENTRIES           37

typedef struct _CMD_TABLE_ENTRY {
    PVOID Cmd;
    union {
        struct _CMD_TABLE_ENTRY *Next;
        SLIST_ENTRY CacheEntry;
    };
} CMD_TABLE_ENTRY, *PCMD_TABLE_ENTRY;

typedef struct _CMD_TABLE {
    SLIST_HEADER Cache;
    SLIST_HEADER FreeCmds;
    PVOID DeviceExtension;
    PCMD_TABLE_ENTRY Entries[CMD_TABLE_ENTRIES];
    volatile LONG Lock[CMD_TABLE_ENTRIES];
} CMD_TABLE, *PCMD_TABLE;



void CmdTableInit(PCMD_TABLE Table, PVOID DeviceExtension);
void CmdTableFinit(PCMD_TABLE Table);
ULONG CmdTableAllocItem(PCMD_TABLE Table, PVOID *Cmd);
void CmdTableClearSrb(PCMD_TABLE Table, PVOID Cmd);
void CmdTableDereferenceItem(PCMD_TABLE Table, PVOID Cmd);
ULONG CmdTableInsert(PCMD_TABLE Table, PVOID Cmd);
BOOLEAN CmdTableDelete(PCMD_TABLE Table, PVOID Cmd);


#endif
