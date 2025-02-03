
#pragma once


#include <ntddk.h>
#include <storport.h>
#include <ntddscsi.h>


#define VIOSTOR_BUFFER_TAG					(ULONG)'BTSV'

typedef struct _SRB_ALIGNED_BUFFER {
	LIST_ENTRY Entry;
	PVOID OrigVA;
	PVOID VA;
	PHYSICAL_ADDRESS PA;
	ULONG Length;
	ULONG AllocLength;
	BOOLEAN Mapped : 1;
	BOOLEAN Allocated : 1;
	BOOLEAN Original : 1;
	BOOLEAN Last : 1;
} SRB_ALIGNED_BUFFER, *PSRB_ALIGNED_BUFFER;

#define VB_ALIGN_FLAG_KEEP_ALIGNED				0x1
#define VB_ALIGN_FLAG_DONT_MOVE					0x2

NTSTATUS VBAllocVAs(PVOID DeviceExtension, const STOR_SCATTER_GATHER_LIST *SGL, ULONG Count, PSRB_ALIGNED_BUFFER *Buffers);
NTSTATUS VBAllocAligned(PVOID DeviceExtension, const SRB_ALIGNED_BUFFER *Buffers, ULONG Alignment, ULONG Flags, PSRB_ALIGNED_BUFFER* Aligned, PULONG Count);
void VBFree(PVOID DeviceExtension, PSRB_ALIGNED_BUFFER Buffers);
void VBCopy(const SRB_ALIGNED_BUFFER* Source, PSRB_ALIGNED_BUFFER Dest);
