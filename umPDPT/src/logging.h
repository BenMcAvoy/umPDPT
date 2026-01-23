#pragma once

#include <ntifs.h>
#include <stdarg.h>
#include <ntstrsafe.h>

namespace umPDPTDriver {
    enum class LogLevel : UINT8 {
        Trace,
        Info,
        Warn,
        Error,
        Fatal
    };

    // Even seq = writing
	// Odd seq = committed
    // Readers must:
    //  - Read seq (acquire)
    //  - Copy entry
    //  - Read seq again
	//  - Accept only if seq is unchanged and odd (committed)
    struct LogEntry {
        volatile LONG seq;
        UINT64 timestamp;
        UINT32 pid;
        UINT32 tid;
        LogLevel level;
        UINT16 length;
        CHAR message[256];
    };

    // ring
    struct LogBuffer {
        volatile LONG writeIndex;
        UINT32 capacity;
        LogEntry entries[1]; // flexible array member
    };

	_IRQL_requires_max_(DISPATCH_LEVEL)
    NTSTATUS LogInit(size_t capacity = 4096);
	_IRQL_requires_max_(DISPATCH_LEVEL)
    void LogShutdown();
	_IRQL_requires_max_(DISPATCH_LEVEL)
    void LogWrite(LogLevel level, const char* fmt, ...);

	LogBuffer** GetLogBuffer();
	PMDL* GetLogMdl();
    PVOID* GetLogMdlMapping();

#define LOG_TRACE(fmt, ...) ::umPDPTDriver::LogWrite(::umPDPTDriver::LogLevel::Trace, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::umPDPTDriver::LogWrite(::umPDPTDriver::LogLevel::Error, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) ::umPDPTDriver::LogWrite(::umPDPTDriver::LogLevel::Info, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) ::umPDPTDriver::LogWrite(::umPDPTDriver::LogLevel::Warn, fmt, ##__VA_ARGS__)
} // namespace umPDPTDriver
