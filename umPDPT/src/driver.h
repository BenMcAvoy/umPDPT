#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <intrin.h>

#include "logging.h"

namespace umPDPTDriver {
	// Constants
	constexpr ULONG CONNCODE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); // attach
	constexpr ULONG MAPCODE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

	// Data
	static PEPROCESS CurrentProcess = nullptr;

	struct MapInfo {
		void* base;       // required
		UINT32 capacity;  // optional
		UINT32 entrySize; // optional
	};

	struct Info_t {
		_In_  DWORD ClientProcessId;
		_Out_ MapInfo MapInfo;
	};

	// Entry
	NTSTATUS NTAPI MainEntryPoint(PDRIVER_OBJECT pDriver, PUNICODE_STRING regPath);

	// General handlers
	NTSTATUS HandleIORequest(PDEVICE_OBJECT pDev, PIRP irp);
	NTSTATUS HandleIOUnsupported(PDEVICE_OBJECT pDeviceObj, PIRP irp);
	NTSTATUS HandleIOCreateClose(PDEVICE_OBJECT pDeviceObj, PIRP irp); // Handles both create and close IRPs

	// Code handlers
	NTSTATUS HandleIOCodeConnect(Info_t* buffer);
	NTSTATUS HandleIOCodeMap(Info_t* buffer);

	// Helpers
	NTSTATUS SaveStringToRegistry(
		_In_ PUNICODE_STRING regPath,
		_In_ PCWSTR valueName,
		_In_ PCWSTR data
	);

	PVOID GetPML4Base();
} // namespace umPDPTDriver
