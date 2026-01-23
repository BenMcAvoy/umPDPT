#include "logging.h"

static umPDPTDriver::LogBuffer* g_LogBuffer = nullptr;

static PMDL g_LogMdl = nullptr;
static PVOID g_LogMdlMapping = nullptr;

NTSTATUS umPDPTDriver::LogInit(size_t capacity) {
    if (capacity == 0 || capacity > MAXLONG) {
        return STATUS_INVALID_PARAMETER;
    }

    const size_t bufferSize = sizeof(LogBuffer) + (capacity - 1) * sizeof(LogEntry);
    auto buffer = static_cast<LogBuffer*>(
        ExAllocatePool2(
            POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, // non paged to allow dispatch level logging
            bufferSize,
            'PDPT' // tag
        )
        );

	if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, bufferSize);

    buffer->capacity = (UINT32)capacity;
    InterlockedExchange(&buffer->writeIndex, -1);

	KeMemoryBarrier(); // ensure initialization is visible before assignment

    g_LogBuffer = buffer;

    g_LogMdl = IoAllocateMdl(
        g_LogBuffer,
        (ULONG)bufferSize,
        FALSE,
        FALSE,
        nullptr
	);

    if (!g_LogMdl) {
		ExFreePool(g_LogBuffer);
        g_LogBuffer = nullptr;
		return STATUS_INSUFFICIENT_RESOURCES;
    }

	MmBuildMdlForNonPagedPool(g_LogMdl);

	return STATUS_SUCCESS;
}

void umPDPTDriver::LogShutdown() {
    if (g_LogBuffer) {
        g_LogBuffer = nullptr;
		KeMemoryBarrier(); // ensure everyone can see it's null before freeing
		ExFreePool(g_LogBuffer);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void umPDPTDriver::LogWrite(
    LogLevel level,
    const char* fmt,
    ...
) {
    auto buf = g_LogBuffer;
    if (!buf) {
        return;
    }

    const LONG i = InterlockedIncrement(&buf->writeIndex);
    LogEntry& e = buf->entries[i % buf->capacity];

    e.seq = i << 1;
    KeMemoryBarrier(); // this is critical that seq write is not reordered

    LARGE_INTEGER qpc = KeQueryPerformanceCounter(NULL);

    e.timestamp = qpc.QuadPart;
    e.pid = HandleToUlong(PsGetCurrentProcessId());
    e.tid = HandleToUlong(PsGetCurrentThreadId());
    e.level = level;

    va_list args;
    va_start(args, fmt);

    NTSTATUS status;
    size_t remaining = 0;

    status = RtlStringCbVPrintfExA(
        e.message,
        sizeof(e.message),
        nullptr,
        &remaining,
        STRSAFE_NO_TRUNCATION,
        fmt,
        args
    );

    va_end(args);

    if (NT_SUCCESS(status)) {
        e.length = static_cast<UINT16>(
            sizeof(e.message) - remaining
            );
    }
    else if (status == STATUS_BUFFER_OVERFLOW) {
        e.length = static_cast<UINT16>(
            sizeof(e.message) - 1
            );
    }
    else {
        e.length = 0;
        e.message[0] = '\0';
    }

	KeMemoryBarrier(); // ensure all writes are visible before seq is committed
	e.seq = (i << 1) | 1; // mark as committed (odd seq)
}

umPDPTDriver::LogBuffer** umPDPTDriver::GetLogBuffer() {
    return &g_LogBuffer;
}
PMDL* umPDPTDriver::GetLogMdl() {
    return &g_LogMdl;
}
PVOID* umPDPTDriver::GetLogMdlMapping() {
    return &g_LogMdlMapping;
}
