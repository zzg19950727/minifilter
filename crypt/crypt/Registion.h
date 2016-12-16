#ifndef REGISTION_H
#define REGISTION_H

#include "Operation.h"

NTSTATUS
InstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
CleanupVolumeContext(
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    );

NTSTATUS
InstanceQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    );

NTSTATUS
FilterUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    );
#endif	//REGISTION_H