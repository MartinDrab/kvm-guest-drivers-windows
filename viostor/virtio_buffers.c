
#include <ntddk.h>
#include <storport.h>
#include <ntddscsi.h>
#include "virtio_buffers.h"
#include "virtio_stor.h"
#if defined(EVENT_TRACING)
#include "virtio_buffers.tmh"
#endif




NTSTATUS VBAllocVAs(PVOID DeviceExtension, const STOR_SCATTER_GATHER_LIST *SGL, ULONG Count, PSRB_ALIGNED_BUFFER *Buffers)
{
	PSRB_ALIGNED_BUFFER tmpBuffers = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	status = StorPortAllocatePool(DeviceExtension, Count*sizeof(SRB_ALIGNED_BUFFER), VIOSTOR_BUFFER_TAG, &tmpBuffers);
	if (NT_SUCCESS(status)) {
		memset(tmpBuffers, 0, Count*sizeof(SRB_ALIGNED_BUFFER));
		for (ULONG i = 0; i < Count; ++i) {
			PSRB_ALIGNED_BUFFER b = tmpBuffers + i;

			InitializeListHead(&b->Entry);
			b->PA = SGL->List[i].PhysicalAddress;
			b->AllocLength = SGL->List[i].Length;
			b->Length = b->AllocLength;
			b->VA = MmMapIoSpace(b->PA, b->AllocLength, MmNonCached);
			if (b->VA == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				for (ULONG j = 0; j < i; ++j) {
					b = tmpBuffers + j;
					MmUnmapIoSpace(b->VA, b->AllocLength);
				}
					
			}

			b->Mapped = TRUE;
			b->Original = TRUE;
			b->Last = (i == Count - 1);
		}
	
		if (NT_SUCCESS(status))
			*Buffers = tmpBuffers;

		if (!NT_SUCCESS(status))
			StorPortFreePool(DeviceExtension, tmpBuffers);
	}

	return status;
}


NTSTATUS VBAllocAligned(PVOID DeviceExtension, const SRB_ALIGNED_BUFFER *Buffers, ULONG Alignment, ULONG Flags, PSRB_ALIGNED_BUFFER *Aligned, PULONG Count)
{
	ULONG tmpCount = 0;
	ULONG dummy = 0;
	LIST_ENTRY head;
	const SRB_ALIGNED_BUFFER *tmp = NULL;
	PSRB_ALIGNED_BUFFER ab = NULL;
	PSRB_ALIGNED_BUFFER currentAB = NULL;
	ULONG bytesRemaining = 0;
	PSRB_ALIGNED_BUFFER old = NULL;
	PSRB_ALIGNED_BUFFER tmpAligned = NULL;
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	status = STATUS_SUCCESS;
	InitializeListHead(&head);
	tmp = Buffers;
	while (NT_SUCCESS(status)) {
		if (currentAB != NULL) {
			if (tmp->Length <= bytesRemaining) {
				bytesRemaining -= tmp->Length;
				if (tmp->Last)
					break;

				++tmp;
				continue;
			}

			currentAB = CONTAINING_RECORD(currentAB->Entry.Flink, SRB_ALIGNED_BUFFER, Entry);
			bytesRemaining = currentAB->Length - tmp->Length;
		}
		
		if ((Flags & VB_ALIGN_FLAG_KEEP_ALIGNED) == 0 ||
			(tmp->PA.QuadPart & (Alignment - 1)) != 0 ||
			(tmp->Length & (0x200 -1)) != 0
			) {
			const ULONG pageCount = (tmp->Length + PAGE_SIZE - 1) / PAGE_SIZE;

			for (ULONG i = 0; i < pageCount; ++i) {
				status = StorPortAllocatePool(DeviceExtension, sizeof(SRB_ALIGNED_BUFFER), VIOSTOR_BUFFER_TAG, &ab);
				if (!NT_SUCCESS(status))
					break;

				memset(ab, 0, sizeof(SRB_ALIGNED_BUFFER));
				InitializeListHead(&ab->Entry);
				status = StorPortAllocatePool(DeviceExtension, 2 * PAGE_SIZE, VIOSTOR_BUFFER_TAG, &ab->OrigVA);
				if (!NT_SUCCESS(status)) {
					RhelDbgPrint(TRACE_LEVEL_ERROR, " StorPortAllocatePool: 0x%x\n", status);
					StorPortFreePool(DeviceExtension, ab);
					break;
				}

				ab->Allocated = TRUE;
				ab->AllocLength = PAGE_SIZE;
				ab->Length = ab->AllocLength;
				if (i == pageCount - 1) {
					ab->Length = tmp->Length % PAGE_SIZE;
					if ((Flags & VB_ALIGN_FLAG_DONT_MOVE) != 0)
						ab->AllocLength = ab->Length;
				}

				ab->VA = (PVOID)(((ULONG_PTR)ab->OrigVA + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
				ab->PA = StorPortGetPhysicalAddress(DeviceExtension, NULL, ab->VA, &dummy);
				if (ab->PA.QuadPart == 0) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					RhelDbgPrint(TRACE_LEVEL_ERROR, " No physical address for 0x%p\n", ab->VA);
					StorPortFreePool(DeviceExtension, ab);
					break;
				}

				InsertTailList(&head, &ab->Entry);
				++tmpCount;
			}

			if (!NT_SUCCESS(status))
				break;
		} else {
			status = StorPortAllocatePool(DeviceExtension, sizeof(SRB_ALIGNED_BUFFER), VIOSTOR_BUFFER_TAG, &ab);
			if (!NT_SUCCESS(status))
				break;

			memset(ab, 0, sizeof(SRB_ALIGNED_BUFFER));
			InitializeListHead(&ab->Entry);
			ab->PA = tmp->PA;
			ab->VA = tmp->VA;
			ab->AllocLength = tmp->AllocLength;
			ab->Length = tmp->Length;
			ab->Original = TRUE;
			InsertTailList(&head, &ab->Entry);
			++tmpCount;
		}

		if (currentAB == NULL &&
			ab->Length > tmp->Length) {
			currentAB = ab;
			bytesRemaining = currentAB->Length - tmp->Length;
		}

		if (tmp->Last)
			break;

		++tmp;
	}

	if (NT_SUCCESS(status)) {
		status = StorPortAllocatePool(DeviceExtension, tmpCount*sizeof(SRB_ALIGNED_BUFFER), VIOSTOR_BUFFER_TAG, &tmpAligned);
		if (NT_SUCCESS(status)) {
			*Aligned = tmpAligned;
			*Count = tmpCount;
			ab = CONTAINING_RECORD(head.Flink, SRB_ALIGNED_BUFFER, Entry);
			while (&ab->Entry != &head) {
				old = ab;
				ab = CONTAINING_RECORD(ab->Entry.Flink, SRB_ALIGNED_BUFFER, Entry);
				*tmpAligned = *old;
				tmpAligned->Last = (old->Entry.Flink == &head);
				++tmpAligned;
				StorPortFreePool(DeviceExtension, old);
			}
		}
	}

	if (!NT_SUCCESS(status)) {
		ab = CONTAINING_RECORD(head.Flink, SRB_ALIGNED_BUFFER, Entry);
		while (&ab->Entry != &head) {
			old = ab;
			ab = CONTAINING_RECORD(ab->Entry.Flink, SRB_ALIGNED_BUFFER, Entry);
			if (old->Allocated)
				StorPortFreePool(DeviceExtension, old->OrigVA);
		
			StorPortFreePool(DeviceExtension, old);
		}
	}

	return status;
}


void VBFree(PVOID DeviceExtension, PSRB_ALIGNED_BUFFER Buffers)
{
	PSRB_ALIGNED_BUFFER tmp = NULL;

	tmp = Buffers;
	while (TRUE) {
		if (tmp->Allocated)
			StorPortFreePool(DeviceExtension, tmp->OrigVA);

		if (tmp->Mapped)
			MmUnmapIoSpace(tmp->VA, tmp->AllocLength);

		if (tmp->Last)
			break;

		++tmp;
	}

	StorPortFreePool(DeviceExtension, Buffers);

	return;
}


void VBCopy(const SRB_ALIGNED_BUFFER *Source, PSRB_ALIGNED_BUFFER Dest)
{
	ULONG bytesToCopy = 0;
	ULONG bytesRemaining = 0;

	bytesRemaining = Source->Length;
	Dest->Length = 0;
	while (TRUE) {
		bytesToCopy = min(bytesRemaining, Dest->AllocLength - Dest->Length);
		memmove((unsigned char *)Dest->VA + Dest->Length, (unsigned char *)Source->VA + Source->Length - bytesRemaining, bytesToCopy);
		Dest->Length += bytesToCopy;
		bytesRemaining -= bytesToCopy;
		if (Dest->Length == Dest->AllocLength) {
			if (Dest->Last)
				break;

			++Dest;
			Dest->Length = 0;
		}

		if (bytesRemaining == 0) {
			if (Source->Last)
				break;

			++Source;
			bytesRemaining = Source->Length;
		}
	}

	return;
}
