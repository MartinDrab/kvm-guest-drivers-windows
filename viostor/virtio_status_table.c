
#include <ntddk.h>
#include "virtio_stor_trace.h"
#include "virtio_status_table.h"
#if defined(EVENT_TRACING)
#include "virtio_status_table.tmh"
#endif



static volatile LONG _statusCount;


static size_t _HashFunctionFirst(ULONG64 Id)
{
	size_t ret = 0;

	ret = (size_t)(
		3*(Id & 0xff) +
		5*((Id >> 8) && 0xff) +
		7*((Id >> 16) && 0xff) +
		11*((Id >> 24) && 0xff) +
		13*((Id >> 32) && 0xff) +
		17*((Id >> 40) && 0xff) +
		19*((Id >> 48) && 0xff) +
		23*((Id >> 56) && 0xff)
	);

	return ret;
}


static size_t _HashFunctionNext(ULONG64 Id, size_t BaseIndex, size_t Attempt)
{
	return (BaseIndex + Attempt*(Id & 0xff));
}


void StatusTableInit(PSTATUS_TABLE Table)
{
	memset(Table->Entries, 0, sizeof(Table->Entries));
	for (size_t i = 0; i < VIRTIO_STATUS_TABLE_SIZE; ++i)
		Table->Entries[i].Status = 0xEE;

	InterlockedExchange(&Table->Lock, 0);

	return;
}


unsigned char *StatusTableInsert(PSTATUS_TABLE Table, ULONG64 Id)
{
	size_t index = 0;
	size_t attempt = 0;
	size_t nextIndex = 0;
	unsigned char *ret = NULL;
	PSTATUS_TABLE_ENTRY entry = NULL;

	while (InterlockedCompareExchange(&Table->Lock, 1, 0))
		__nop();

	index = _HashFunctionFirst(Id) % VIRTIO_STATUS_TABLE_SIZE;
	nextIndex = index;
	do {
		entry = Table->Entries + nextIndex;
		if (!entry->Present || entry->Deleted) {
			entry->Present = 1;
			entry->Deleted = 0;
			entry->Id = Id;
			ret = &entry->Status;
			InterlockedIncrement(&_statusCount);
			break;
		}

		++attempt;
		nextIndex = _HashFunctionNext(Id, index, attempt) % VIRTIO_STATUS_TABLE_SIZE;
	} while (index != nextIndex);

	InterlockedExchange(&Table->Lock, 0);
	if (index == nextIndex && attempt > 0) {
		RhelDbgPrint(TRACE_LEVEL_WARNING, " Unable to insert status for ID %llu\n", Id);
	}

	return ret;
}


void StatusTableDelete(PSTATUS_TABLE Table, ULONG64 Id, unsigned char *Status)
{
	size_t index = 0;
	size_t attempt = 0;
	size_t nextIndex = 0;
	unsigned char* ret = NULL;
	PSTATUS_TABLE_ENTRY entry = NULL;

	while (InterlockedCompareExchange(&Table->Lock, 1, 0))
		__nop();

	index = _HashFunctionFirst(Id) % VIRTIO_STATUS_TABLE_SIZE;
	nextIndex = index;
	do {
		entry = Table->Entries + nextIndex;
		if (!entry->Present && !entry->Deleted) {
			nextIndex = index;
			attempt = 1;
			break;
		}

		if (entry->Present && entry->Id == Id) {
			entry->Deleted = 1;
			entry->Present = 0;
			entry->Id = 0;
			if (Status != NULL)
				*Status = entry->Status;

			entry->Status = 0xEE;
			InterlockedDecrement(&_statusCount);
			break;
		}

		++attempt;
		nextIndex = _HashFunctionNext(Id, index, attempt) % VIRTIO_STATUS_TABLE_SIZE;
	} while (index != nextIndex);

	InterlockedExchange(&Table->Lock, 0);
	if (index == nextIndex && attempt > 0) {
		RhelDbgPrint(TRACE_LEVEL_ERROR, " Unable to delete status for ID %llu\n", Id);
		__debugbreak();
	}

	return;
}
