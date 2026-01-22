#pragma once

#include <Windows.h>

#include <string>
#include <string_view>

#include <stdexcept>

namespace umPDPTClient {
	// Constants
	constexpr ULONG CONNCODE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); // attach

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

		void Connect() const {
			if (hDevice_ == INVALID_HANDLE_VALUE) {
				throw std::runtime_error("Device handle is invalid.");
			}

			DWORD currentPID = GetCurrentProcessId();
			DWORD bytesReturned = 0;

			BOOL result = DeviceIoControl(
				hDevice_,
				CONNCODE,
				&currentPID,
				sizeof(currentPID),
				nullptr,
				0,
				&bytesReturned,
				nullptr
			);

			if (!result) {
				throw std::runtime_error("DeviceIoControl failed to connect to the driver.");
			}
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
	};
} // namespace umPDPTClient
