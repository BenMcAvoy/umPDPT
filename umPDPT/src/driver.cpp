#include "driver.h"

NTSTATUS umPDPTDriver::MainEntryPoint(PDRIVER_OBJECT pDriver, PUNICODE_STRING regPath) {
	UNREFERENCED_PARAMETER(regPath);

	NTSTATUS status;

	PDEVICE_OBJECT pDev = nullptr;

	WCHAR deviceNameBuf[64];
	ULONG64 count = __rdtsc();
	swprintf(deviceNameBuf, L"\\Device\\umPDPTDevice_%llu", count);
	UNICODE_STRING devName = RTL_CONSTANT_STRING(deviceNameBuf);

	status = IoCreateDevice(pDriver, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDev);
	if (!NT_SUCCESS(status)) {
		LOG_ERROR("IoCreateDevice failed: 0x%X", status);
		return status;
	}

	LOG_TRACE("Device created successfully");

	WCHAR symLinkBuf[64];
	swprintf(symLinkBuf, L"\\DosDevices\\Global\\umPDPTLink_%llu", count);
	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, symLinkBuf);

	WCHAR umLinkNameBuf[64];
	swprintf(umLinkNameBuf, L"umPDPTLink_%llu", count);

	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		LOG_ERROR("IoCreateSymbolicLink failed: 0x%X", status);
		IoDeleteDevice(pDev);
		return status;
	}

	// Save symlink path to registry
	UNICODE_STRING regPathStr = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\umPDPT");
	status = SaveStringToRegistry(&regPathStr, L"SymlinkName", umLinkNameBuf);
	if (!NT_SUCCESS(status)) {
		LOG_ERROR("SaveStringToRegistry failed: 0x%X", status);
		IoDeleteDevice(pDev);
		return status;
	}

	LOG_TRACE("Symbolic link created successfully");
	pDriver->MajorFunction[IRP_MJ_CREATE] = umPDPTDriver::HandleIOCreateClose;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = umPDPTDriver::HandleIOCreateClose;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = umPDPTDriver::HandleIORequest;

	ClearFlag(pDev->Flags, DO_DEVICE_INITIALIZING);

	LOG_TRACE("Driver entry point completed successfully");

	return STATUS_SUCCESS;
}

NTSTATUS umPDPTDriver::HandleIORequest(PDEVICE_OBJECT pDev, PIRP irp) {
	UNREFERENCED_PARAMETER(pDev);

	irp->IoStatus.Information = sizeof(Info_t);

	auto stack = IoGetCurrentIrpStackLocation(irp);
	if (!stack) {
		irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	auto code = stack->Parameters.DeviceIoControl.IoControlCode;

	auto buffer = static_cast<Info_t*>(irp->AssociatedIrp.SystemBuffer);
	if (!buffer) {
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	switch (code) {
	case CONNCODE:
		status = HandleIOCodeConnect(buffer);
		break;
	case MAPCODE:
		status = HandleIOCodeMap(buffer);
		break;
	default:
		status = HandleIOUnsupported(pDev, irp);
		return status;
	}

	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS umPDPTDriver::HandleIOCodeConnect(Info_t* buffer) {
	UNREFERENCED_PARAMETER(buffer);

	WCHAR msgBuf[128];
	swprintf(msgBuf, L"Client process connected. PID: %u", buffer->ClientProcessId);
	LOG_INFO("%ws", msgBuf);

	// Open process
	NTSTATUS res = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(buffer->ClientProcessId), &CurrentProcess);
	if (!NT_SUCCESS(res)) {
		LOG_ERROR("PsLookupProcessByProcessId failed: 0x%X", res);
		return res;
	}

	LOG_INFO("Client process handle obtained successfully @ 0x%p", CurrentProcess);

	KAPC_STATE apcState;
	KeStackAttachProcess(CurrentProcess, &apcState);

	auto logBuffer = *GetLogBuffer();
	auto logMdl = *GetLogMdl();
	auto logMdlMapping = GetLogMdlMapping();

	PVOID userVA = MmMapLockedPagesSpecifyCache(
		logMdl,
		UserMode,
		MmNonCached,
		nullptr,
		FALSE,
		NormalPagePriority
	);

	KeUnstackDetachProcess(&apcState);

	DbgPrint(
		"umPDPT: Log buffer mapped to user mode at address 0x%p\n",
		userVA
	);

	if (!userVA) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	*logMdlMapping = userVA;

	// Fill log map info
	buffer->MapInfo.base = userVA;
	buffer->MapInfo.capacity = logBuffer->capacity;
	buffer->MapInfo.entrySize = sizeof(LogEntry);

	return STATUS_SUCCESS;
}

NTSTATUS umPDPTDriver::HandleIOCodeMap(Info_t* buffer) {
	UNREFERENCED_PARAMETER(buffer);

	PVOID base = GetPML4Base();
	buffer->MapInfo.base = base;
	LOG_TRACE("Provided PML4 base to client: 0x%p", base);

	// TODO: real behavior

	return STATUS_SUCCESS;
}

NTSTATUS umPDPTDriver::HandleIOUnsupported(PDEVICE_OBJECT pDeviceObj, PIRP irp) {
	UNREFERENCED_PARAMETER(pDeviceObj);
	UNREFERENCED_PARAMETER(irp);

	LOG_WARN("Unsupported IO request received");

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_NOT_SUPPORTED;
}

NTSTATUS umPDPTDriver::HandleIOCreateClose(PDEVICE_OBJECT pDeviceObj, PIRP irp) {
	UNREFERENCED_PARAMETER(pDeviceObj);

	LOG_INFO("Create/Close request received");

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS umPDPTDriver::SaveStringToRegistry(
	_In_ PUNICODE_STRING regPath,
	_In_ PCWSTR valueNameRaw,
	_In_ PCWSTR data
) {
	OBJECT_ATTRIBUTES oa{};
	InitializeObjectAttributes(
		&oa,
		regPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		nullptr,
		nullptr
	);

	HANDLE hKey;
	NTSTATUS status = ZwCreateKey(
		&hKey,
		KEY_ALL_ACCESS,
		&oa,
		0,
		nullptr,
		REG_OPTION_NON_VOLATILE,
		nullptr
	);

	if (!NT_SUCCESS(status)) {
		LOG_ERROR("ZwCreateKey failed: 0x%X", status);
		return status;
	}

	SIZE_T byteSize = (wcslen(data) + 1) * sizeof(WCHAR);

	UNICODE_STRING valueName;
	RtlInitUnicodeString(&valueName, valueNameRaw);

	status = ZwSetValueKey(
		hKey,
		&valueName,
		0,
		REG_SZ,
		const_cast<PWSTR>(data),
		static_cast<ULONG>(byteSize)
	);

	ZwClose(hKey);

	if (!NT_SUCCESS(status)) {
		LOG_ERROR("ZwSetValueKey failed: 0x%X", status);
		return status;
	}

	LOG_TRACE("String saved to registry successfully");
	return STATUS_SUCCESS;
}

PVOID umPDPTDriver::GetPML4Base() {
	if (!CurrentProcess) {
		LOG_ERROR("CurrentProcess is null");
		return nullptr;
	}

	// Offset 0x28 in EPROCESS is the DirectoryTableBase (PML4) https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_KPROCESS
	// NOTE: Win11 24H2 and Win10 22H2 have the same offset. As of Jan 2026, this seems stable enough to hardcode.

	constexpr SIZE_T offset_DirectoryTableBase = 0x28;
	PVOID pml4Base = *reinterpret_cast<PVOID*>(reinterpret_cast<UINT8*>(CurrentProcess) + offset_DirectoryTableBase);
	LOG_TRACE("PML4 Base obtained: 0x%p", pml4Base);

	return pml4Base;
}