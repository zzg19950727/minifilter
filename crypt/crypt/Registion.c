#include "Registion.h"
#include "CryptStrategy.h"
#include "driver.h"
#include "crypt.h"
#include "common.h"
#include "whiteName.h"
#include "Operation.h"
#include <wdm.h>

extern LIST_ENTRY list_head;
extern KSPIN_LOCK list_lock;

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PreCreate,
	  PostCreate },

    { IRP_MJ_CLOSE,
      0,
      NULL,//PreClose,
      NULL},//PostClose },

    { IRP_MJ_READ,
      0,
      SwapPreReadBuffers,
	  SwapPostReadBuffers },

    { IRP_MJ_WRITE,
      0,
      SwapPreWriteBuffers,
	  SwapPostWriteBuffers },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      PreQueryInformation,
	  PostQueryInformation },

    { IRP_MJ_SET_INFORMATION,
      0,
      PreSetInformation,
	  PostSetInformation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      SwapPreDirCtrlBuffers,
      SwapPostDirCtrlBuffers },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      PreNetworkOpen,
      PostNetworkOpen },

    { IRP_MJ_OPERATION_END }
};

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, InstanceSetup)
#pragma alloc_text(PAGE, CleanupVolumeContext)
#pragma alloc_text(PAGE, InstanceQueryTeardown)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, ReadDriverParameters)
#pragma alloc_text(PAGE, FilterUnload)
#endif

CONST FLT_CONTEXT_REGISTRATION ContextNotifications[] = {

     { FLT_VOLUME_CONTEXT,
       0,
       CleanupVolumeContext,
       sizeof(VOLUME_CONTEXT),
       CONTEXT_TAG },

     { FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    ContextNotifications,               //  Context
    Callbacks,                          //  Operation callbacks

    FilterUnload,                       //  MiniFilterUnload

    InstanceSetup,                      //  InstanceSetup
    InstanceQueryTeardown,              //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

PFLT_FILTER gFilterHandle;
PFLT_PORT gServerPort;
PFLT_PORT gClientPort;
BOOLEAN service_enable = FALSE;

NPAGED_LOOKASIDE_LIST Pre2PostContextList;

NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;

    ReadDriverParameters( RegistryPath );
	
	InitializeListHead(&list_head);
	
	KeInitializeSpinLock(&list_lock);
	
	LoggingFlags	= 0x00000100;

    ExInitializeNPagedLookasideList( &Pre2PostContextList,
                                     NULL,
                                     NULL,
                                     0,
                                     sizeof(PRE_2_POST_CONTEXT),
                                     PRE_2_POST_TAG,
                                     0 );

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    if (! NT_SUCCESS( status )) {

        goto SwapDriverEntryExit;
    }

	status  = FltBuildDefaultSecurityDescriptor( &sd,FLT_PORT_ALL_ACCESS );

		if (!NT_SUCCESS( status )) 
		{
			FltUnregisterFilter( gFilterHandle );
			goto SwapDriverEntryExit;
		}

		RtlInitUnicodeString( &uniString, MINISPY_PORT_NAME );

		InitializeObjectAttributes( &oa,
			&uniString,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			sd );

		status = FltCreateCommunicationPort( gFilterHandle,
			&gServerPort,
			&oa,
			NULL,
			SpyConnect,
			SpyDisconnect,
			SpyMessage,
			1 );

		FltFreeSecurityDescriptor( sd );

		if (!NT_SUCCESS( status )) 
		{
			FltUnregisterFilter( gFilterHandle );
			goto SwapDriverEntryExit;
		}
    status = FltStartFiltering( gFilterHandle );

    if (! NT_SUCCESS( status )) {

        FltUnregisterFilter( gFilterHandle );
        goto SwapDriverEntryExit;
    }
	
SwapDriverEntryExit:

    if(! NT_SUCCESS( status )) {

        ExDeleteNPagedLookasideList( &Pre2PostContextList );
    }
	CurProcNameInit();
    return status;
}

NTSTATUS
FilterUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
	
    PAGED_CODE();

    UNREFERENCED_PARAMETER( Flags );

	ClearWhiteNameList();

	FltCloseCommunicationPort( gServerPort );

    FltUnregisterFilter( gFilterHandle );

    ExDeleteNPagedLookasideList( &Pre2PostContextList );

    return STATUS_SUCCESS;
}

NTSTATUS
InstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    PDEVICE_OBJECT devObj = NULL;
    PVOLUME_CONTEXT ctx = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG retLen;
    PUNICODE_STRING workingName;
    USHORT size;
    UCHAR volPropBuffer[sizeof(FLT_VOLUME_PROPERTIES)+512];
    PFLT_VOLUME_PROPERTIES volProp = (PFLT_VOLUME_PROPERTIES)volPropBuffer;

    PAGED_CODE();

    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    try {
        status = FltAllocateContext( FltObjects->Filter,
                                     FLT_VOLUME_CONTEXT,
                                     sizeof(VOLUME_CONTEXT),
                                     PagedPool,
                                     &ctx );

        if (!NT_SUCCESS(status)) 
		{
            leave;
        }

        status = FltGetVolumeProperties( FltObjects->Volume,
                                         volProp,
                                         sizeof(volPropBuffer),
                                         &retLen );

        if (!NT_SUCCESS(status))
		{
            leave;
        }
        ASSERT((volProp->SectorSize == 0) || (volProp->SectorSize >= MIN_SECTOR_SIZE));

        ctx->SectorSize = max(volProp->SectorSize,MIN_SECTOR_SIZE);
        ctx->Name.Buffer = NULL;

        status = FltGetDiskDeviceObject( FltObjects->Volume, &devObj );

        if (NT_SUCCESS(status)) 
		{
	#pragma prefast(suppress:__WARNING_USE_OTHER_FUNCTION, \
	"Used to maintain compatability with Win 2k")
            status = RtlVolumeDeviceToDosName( devObj, &ctx->Name );
        }
        if (!NT_SUCCESS(status))
		{
            ASSERT(ctx->Name.Buffer == NULL);
            if (volProp->RealDeviceName.Length > 0) 
			{
                workingName = &volProp->RealDeviceName;
            } 
			else if (volProp->FileSystemDeviceName.Length > 0) 
			{
                workingName = &volProp->FileSystemDeviceName;
            } 
			else 
			{
                status = STATUS_FLT_DO_NOT_ATTACH;
                leave;
            }

            size = workingName->Length + sizeof(WCHAR);

			#pragma prefast(suppress:__WARNING_MEMORY_LEAK, \
			"ctx->Name.Buffer will not be leaked because it is freed in CleanupVolumeContext")

            ctx->Name.Buffer = ExAllocatePoolWithTag( PagedPool,
                                                      size,
                                                      NAME_TAG );
            if (ctx->Name.Buffer == NULL)
			{
                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }
            ctx->Name.Length = 0;
            ctx->Name.MaximumLength = size;

            RtlCopyUnicodeString( &ctx->Name,
                                  workingName );

            RtlAppendUnicodeToString( &ctx->Name,
                                      L":" );
        }
        status = FltSetVolumeContext( FltObjects->Volume,
                                      FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                      ctx,
                                      NULL );

        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) 
		{
            status = STATUS_SUCCESS;
        }

    }
	finally 
	{
        if (ctx) 
		{
            FltReleaseContext( ctx );
        }

        if (devObj) 
		{
            ObDereferenceObject( devObj );
        }
    }

    return status;
}


VOID
CleanupVolumeContext(
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    )
{
    PVOLUME_CONTEXT ctx = (PVOLUME_CONTEXT)Context;

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ContextType );

    ASSERT(ContextType == FLT_VOLUME_CONTEXT);

    if (ctx->Name.Buffer != NULL) 
	{
        ExFreePool(ctx->Name.Buffer);
        ctx->Name.Buffer = NULL;
    }
}


NTSTATUS
InstanceQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    return STATUS_SUCCESS;
}

NTSTATUS
SpyConnect(
		   __in PFLT_PORT ClientPort,
		   __in PVOID ServerPortCookie,
		   __in_bcount(SizeOfContext) PVOID ConnectionContext,
		   __in ULONG SizeOfContext,
		   __deref_out_opt PVOID *ConnectionCookie
		   )
{

	PAGED_CODE();

	UNREFERENCED_PARAMETER( ServerPortCookie );
	UNREFERENCED_PARAMETER( ConnectionContext );
	UNREFERENCED_PARAMETER( SizeOfContext);
	UNREFERENCED_PARAMETER( ConnectionCookie );


	gClientPort = ClientPort;
	return STATUS_SUCCESS;
}

VOID
SpyDisconnect(
			  __in_opt PVOID ConnectionCookie
			  )
{

	PAGED_CODE();

	UNREFERENCED_PARAMETER( ConnectionCookie );


	FltCloseClientPort( gFilterHandle, &gClientPort );
}

NTSTATUS
SpyMessage (
			__in PVOID ConnectionCookie,
			__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
			__in ULONG InputBufferSize,
			__out_bcount_part_opt(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
			__in ULONG OutputBufferSize,
			__out PULONG ReturnOutputBufferLength
			)
{
	INPUT_BUFFER inputBuf;
	MY_COMMAND command;

	RtlZeroMemory(&inputBuf, sizeof(INPUT_BUFFER));

	if ( (InputBuffer == NULL) || (InputBufferSize > sizeof(INPUT_BUFFER)))
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlCopyMemory(&inputBuf, InputBuffer, InputBufferSize);

	command = inputBuf.command;

	switch (command)
	{
	case ADD_PROTECTED_PATH: //开始隐藏指定目录下的，指定的扩展名文件
		AddNameToWhiteNameList(inputBuf.protectedPath, inputBuf.fileType);
		break;

	case DEL_PROTECTED_PATH: //取消隐藏指定的扩展名文件
		DelNameFromWhiteNameList(inputBuf.protectedPath, inputBuf.fileType);
		break;
		
	case START_SERVICE:
		service_enable = TRUE;
		break;
		
	case STOP_SERVICE:
		service_enable = FALSE;
		break;
		
	default:
		break;
	}

	return STATUS_SUCCESS;
}


#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, InstanceSetup)
#pragma alloc_text(PAGE, CleanupVolumeContext)
#pragma alloc_text(PAGE, InstanceQueryTeardown)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, ReadDriverParameters)
#pragma alloc_text(PAGE, FilterUnload)
#endif