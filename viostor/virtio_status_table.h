
#ifndef __VIRTIO_STATUS_TABLE_H__
#define __VIRTIO_STATUS_TABLE_H__

#include <ntddk.h>



typedef struct _STATUS_TABLE_ENTRY {
	unsigned char Status;
	ULONG64 Id;
	int Present : 1;
	int Deleted : 1;
} STATUS_TABLE_ENTRY, *PSTATUS_TABLE_ENTRY;

#define VIRTIO_STATUS_TABLE_SIZE			769

typedef struct _STATUS_TABLE {
	STATUS_TABLE_ENTRY Entries[VIRTIO_STATUS_TABLE_SIZE];
	volatile LONG Lock;
} STATUS_TABLE, *PSTATUS_TABLE;


void StatusTableInit(PSTATUS_TABLE Table);
unsigned char *StatusTableInsert(PSTATUS_TABLE Table, ULONG64 Id);
void StatusTableDelete(PSTATUS_TABLE Table, ULONG64 Id, unsigned char *Status);



#endif
