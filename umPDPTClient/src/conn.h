#pragma once

#include <Windows.h>

#include <string>
#include <string_view>
#include <thread>
#include <stdexcept>
#include <iostream>
#include <print>
#include <iomanip>
#include <mutex>

namespace umPDPTClient {
	// Constants
	constexpr ULONG CONNCODE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); // attach
	constexpr ULONG MAPCODE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

	// Helpers
	std::string ReadStringFromRegistry(
		std::string_view keyPath,
		std::string_view valueName
	) {
		HKEY hKey = NULL;
		LONG res = RegOpenKeyExA(
			HKEY_LOCAL_MACHINE,
			keyPath.data(),
			0,
			KEY_READ,
			&hKey
		);

		if (res != ERROR_SUCCESS) {
			return {};
		}

		CHAR buffer[256]{};
		DWORD bufSize = sizeof(buffer);

		res = RegQueryValueExA(
			hKey,
			valueName.data(),
			nullptr,
			nullptr,
			reinterpret_cast<LPBYTE>(buffer),
			&bufSize
		);
		RegCloseKey(hKey);

		if (res != ERROR_SUCCESS) {
			return {};
		}

		return std::string(buffer);
	}

	class Driver {
	public:
		static Driver& GetInstance() {
			static Driver instance;
			return instance;
		}

		HANDLE GetDeviceHandle() const {
			return hDevice_;
		}

		void Connect() {
			if (hDevice_ == INVALID_HANDLE_VALUE) {
				throw std::runtime_error("Device handle is invalid.");
			}

			DWORD currentPID = GetCurrentProcessId();
			DWORD bytesReturned = 0;

			Info_t info{};
			info.ClientProcessId = currentPID;

			BOOL result = DeviceIoControl(
				hDevice_,
				CONNCODE,
				&info,
				sizeof(Info_t),
				&info,
				sizeof(Info_t),
				&bytesReturned,
				nullptr
			);

			if (!result) {
				throw std::runtime_error("DeviceIoControl failed to connect to the driver.");
			}

			if (sizeof(LogEntry) != info.MapInfo.entrySize) {
				throw std::runtime_error("Log entry size mismatch.");
			}

			logBuffer_ = reinterpret_cast<LogBuffer*>(info.MapInfo.base);
			std::thread logThread(&Driver::LogReaderThread, this);
			logThread.detach();
		}

		void Map() {
			Info_t info{};

			DWORD bytesReturned = 0;
			BOOL result = DeviceIoControl(
				hDevice_,
				MAPCODE,
				&info,
				sizeof(Info_t),
				&info,
				sizeof(Info_t),
				&bytesReturned,
				nullptr
			);

			// print buffer base
			std::println("PML4: {:p}", info.MapInfo.base);
		}

	private:
		Driver() {
			auto symlinkName = ReadStringFromRegistry("SOFTWARE\\umPDPT", "SymlinkName");
			if (symlinkName.empty()) {
				hDevice_ = INVALID_HANDLE_VALUE;
				return;
			}

			std::string devicePath = "\\\\.\\" + symlinkName;
			hDevice_ = CreateFileA(
				devicePath.c_str(),
				GENERIC_READ | GENERIC_WRITE,
				0,
				nullptr,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				nullptr
			);

			if (hDevice_ == INVALID_HANDLE_VALUE) {
				throw std::runtime_error("Failed to open device handle.");
			}
		}

		~Driver() {
			if (hDevice_ != INVALID_HANDLE_VALUE) {
				CloseHandle(hDevice_);
			}
		}

		HANDLE hDevice_ = INVALID_HANDLE_VALUE;

		struct Info_t {
			DWORD ClientProcessId;
			struct MapInfo {
				void* base;
				UINT32 capacity;
				UINT32 entrySize;
			} MapInfo;
		};

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

		LogBuffer* logBuffer_ = nullptr;

		void LogReaderThread() {
			UINT32 lastIndex = 0;

			for (;;) {
				LONG writeIndex = logBuffer_->writeIndex;

				while (lastIndex != writeIndex) {
					LogEntry& entry = logBuffer_->entries[lastIndex % logBuffer_->capacity];

					LONG seq;
					LogEntry cpy;

					do {
						seq = entry.seq;
						std::memcpy(&cpy, &entry, sizeof(LogEntry));
					} while (seq != cpy.seq || (seq & 1) == 0);

					PrettyPrintLogEntry(
						cpy.timestamp,
						cpy.pid,
						cpy.tid,
						cpy.level,
						std::string_view(cpy.message, cpy.length)
					);

					lastIndex++;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(10));
			}
		}

		static constexpr const char* RESET = "\033[0m";
		static constexpr const char* GRAY = "\033[90m";
		static constexpr const char* BLUE = "\033[34m";
		static constexpr const char* YELLOW = "\033[33m";
		static constexpr const char* RED = "\033[31m";
		static constexpr const char* MAGENTA = "\033[35m";

		const char* GetColor(LogLevel level) {
			switch (level) {
			case LogLevel::Trace: return GRAY;
			case LogLevel::Info:  return BLUE;
			case LogLevel::Warn:  return YELLOW;
			case LogLevel::Error: return RED;
			case LogLevel::Fatal: return MAGENTA;
			default: return RESET;
			}
		}

		const char* GetLevelName(LogLevel level) {
			switch (level) {
			case LogLevel::Trace: return "TRACE";
			case LogLevel::Info:  return "INFO";
			case LogLevel::Warn:  return "WARN";
			case LogLevel::Error: return "ERROR";
			case LogLevel::Fatal: return "FATAL";
			default: return "UNKNOWN";
			}
		}

		void PrettyPrintLogEntry(UINT64 timestamp, UINT32 pid, UINT32 tid, LogLevel level, std::string_view msg) {
			const char* color = GetColor(level);

			std::cout << color
				<< "[" << std::setw(12) << timestamp << "] "
				<< std::setw(5) << GetLevelName(level) << " "
				<< "(PID: " << std::setw(5) << pid
				<< ", TID: " << std::setw(5) << tid << "): "
				<< msg
				<< RESET
				<< "\n";
		}
	};
} // namespace umPDPTClient
