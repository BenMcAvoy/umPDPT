#include "logging.h"
#include "driver.h"

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	umPDPTDriver::LogInit();

	LOG_INFO("umPDPTDriver DriverEntry called");

	WCHAR driverNameBuf[64];
	ULONG64 count = __rdtsc();
	swprintf(driverNameBuf, L"\\Driver\\umPDPTDriver_%llu", count);
	UNICODE_STRING driverName = RTL_CONSTANT_STRING(driverNameBuf);

	NTSTATUS createRes = IoCreateDriver(
		&driverName,
		umPDPTDriver::MainEntryPoint
	);

	if (!NT_SUCCESS(createRes)) {
		LOG_ERROR("IoCreateDriver failed: 0x%X", createRes);
		return createRes;
	}

	LOG_INFO("umPDPTDriver loaded successfully");
	return STATUS_SUCCESS;
}