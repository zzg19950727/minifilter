#include "driver.h"
#include "crypt.h"
#include "Operation.h"
#include "whiteName.h"

VOID GetVolumeName(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__inout PUNICODE_STRING name)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOLUME_CONTEXT volCtx = NULL;

	ASSERT(name);
	
	status = FltGetVolumeContext( FltObjects->Filter,
                                      FltObjects->Volume,
                                      &volCtx );
	if( NT_SUCCESS(status) )
	{
		RtlCopyUnicodeString( name, &volCtx->Name );
	}
	
	FltReleaseContext( volCtx );
}

VOID
GetFullPath(__inout PFLT_CALLBACK_DATA Data,
			__in PCFLT_RELATED_OBJECTS FltObjects,
			__inout PUNICODE_STRING path)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	
	WCHAR buffer1[10];
	PWCHAR buffer2;
	UNICODE_STRING Volume;
	UNICODE_STRING part = RTL_CONSTANT_STRING(L"\\??\\");
	ULONG Len;
	
	RtlInitEmptyUnicodeString(&Volume, buffer1, 10*sizeof(WCHAR));
	GetVolumeName(FltObjects, &Volume);
	
	Len = Volume.Length+file_object->FileName.Length+6+MY_NAME;
	buffer2 = ExAllocatePoolWithTag(PagedPool, Len*sizeof(WCHAR), MEM_TAG);
	if( buffer2 == NULL )
		return;
	
	RtlInitEmptyUnicodeString(path, buffer2, Len*sizeof(WCHAR));
	
	RtlCopyUnicodeString(path, &part);
	RtlAppendUnicodeStringToString(path, &Volume);
	RtlAppendUnicodeStringToString(path, &file_object->FileName);
}

VOID GetTmpPath(__inout PUNICODE_STRING path)
{
	UNICODE_STRING tmp = RTL_CONSTANT_STRING(L".sec");
	RtlAppendUnicodeStringToString(path, &tmp);
}

VOID WriteFileSkipHead(PFLT_PARAMETERS para)
{
	if( para->Write.ByteOffset.QuadPart == 0)
		para->Write.Length += FILE_HEAD_LEN;
}

VOID FreePath(PUNICODE_STRING path)
{
	ExFreePoolWithTag(path->Buffer, MEM_TAG);
}

VOID
ReadDriverParameters (
    __in PUNICODE_STRING RegistryPath
    )
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE driverRegKey;
    NTSTATUS status;
    ULONG resultLength;
    UNICODE_STRING valueName;
    UCHAR buffer[sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof( LONG )];

    //
    //  If this value is not zero then somebody has already explicitly set it
    //  so don't override those settings.
    //

    if (0 == LoggingFlags) {

        //
        //  Open the desired registry key
        //

        InitializeObjectAttributes( &attributes,
                                    RegistryPath,
                                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                    NULL,
                                    NULL );

        status = ZwOpenKey( &driverRegKey,
                            KEY_READ,
                            &attributes );

        if (!NT_SUCCESS( status )) {

            return;
        }

        //
        // Read the given value from the registry.
        //

        RtlInitUnicodeString( &valueName, L"DebugFlags" );

        status = ZwQueryValueKey( driverRegKey,
                                  &valueName,
                                  KeyValuePartialInformation,
                                  buffer,
                                  sizeof(buffer),
                                  &resultLength );

        if (NT_SUCCESS( status )) {

            LoggingFlags = *((PULONG) &(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
        }

        //
        //  Close the registry entry
        //

        ZwClose(driverRegKey);
    }
}

VOID ClearCache(__in PFILE_OBJECT pFileObject)
{
   PFSRTL_COMMON_FCB_HEADER pFcb;
   LARGE_INTEGER liInterval;
   BOOLEAN bNeedReleaseResource = FALSE;
   BOOLEAN bNeedReleasePagingIoResource = FALSE;
   KIRQL irql;

   if (pFileObject->SectionObjectPointer)
   {
		IO_STATUS_BLOCK ioStatus;
		CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);
		CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, FALSE);
   }
   return;
   pFcb = (PFSRTL_COMMON_FCB_HEADER)pFileObject->FsContext;
   if(pFcb == NULL)
       return;

   irql = KeGetCurrentIrql();
   if (irql >= DISPATCH_LEVEL)
   {
       return;
   }

   liInterval.QuadPart = -1 * (LONGLONG)50;

   while (TRUE)
   {
       BOOLEAN bBreak = TRUE;
       BOOLEAN bLockedResource = FALSE;
       BOOLEAN bLockedPagingIoResource = FALSE;
       bNeedReleaseResource = FALSE;
       bNeedReleasePagingIoResource = FALSE;

	   // 到fcb中去拿锁。
       if (pFcb->PagingIoResource)
           bLockedPagingIoResource = ExIsResourceAcquiredExclusiveLite(pFcb->PagingIoResource);

	   // 总之一定要拿到这个锁。
       if (pFcb->Resource)
       {
           bLockedResource = TRUE;
           if (ExIsResourceAcquiredExclusiveLite(pFcb->Resource) == FALSE)
           {
               bNeedReleaseResource = TRUE;
               if (bLockedPagingIoResource)
               {
                   if (ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE) == FALSE)
                   {
                       bBreak = FALSE;
                       bNeedReleaseResource = FALSE;
                       bLockedResource = FALSE;
                   }
               }
               else
                   ExAcquireResourceExclusiveLite(pFcb->Resource, TRUE);
           }
       }
   
       if (bLockedPagingIoResource == FALSE)
       {
           if (pFcb->PagingIoResource)
           {
               bLockedPagingIoResource = TRUE;
               bNeedReleasePagingIoResource = TRUE;
               if (bLockedResource)
               {
                   if (ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE) == FALSE)
                   {
                       bBreak = FALSE;
                       bLockedPagingIoResource = FALSE;
                       bNeedReleasePagingIoResource = FALSE;
                   }
               }
               else
               {
                   ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, TRUE);
               }
           }
       }

       if (bBreak)
       {
           break;
       }
       
       if (bNeedReleasePagingIoResource)
       {
           ExReleaseResourceLite(pFcb->PagingIoResource);
       }
       if (bNeedReleaseResource)
       {
           ExReleaseResourceLite(pFcb->Resource);
       }

       if (irql == PASSIVE_LEVEL)
       {
           KeDelayExecutionThread(KernelMode, FALSE, &liInterval);
       }
       else
       {
           KEVENT waitEvent;
           KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
           KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, &liInterval);
       }
   }

   if (pFileObject->SectionObjectPointer)
   {
		IO_STATUS_BLOCK ioStatus;
		CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);
		if (pFileObject->SectionObjectPointer->ImageSectionObject)
		{
			MmFlushImageSection(pFileObject->SectionObjectPointer,MmFlushForWrite); // MmFlushForDelete
		}
		CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, FALSE);
   }

   if (bNeedReleasePagingIoResource)
   {
       ExReleaseResourceLite(pFcb->PagingIoResource);
   }
   if (bNeedReleaseResource)
   {
       ExReleaseResourceLite(pFcb->Resource);
   }
}

NTSTATUS FileMonQuerySymbolicLink(
						 IN PUNICODE_STRING SymbolicLinkName,
						 OUT PUNICODE_STRING LinkTarget
						 )
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS status;
	HANDLE h;

	InitializeObjectAttributes(&oa, SymbolicLinkName, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,0, 0);

	status = ZwOpenSymbolicLinkObject(&h, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status)) 
	{
		return status;
	}

	LinkTarget->MaximumLength = 200*sizeof(WCHAR);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength,'dsf ');
	if (!LinkTarget->Buffer) 
	{
		ZwClose(h);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

	status = ZwQuerySymbolicLinkObject(h, LinkTarget, NULL);

	ZwClose(h);

	if (!NT_SUCCESS(status)) 
	{
		ExFreePoolWithTag(LinkTarget->Buffer,'dsf ');
	}

	return status;
}


NTSTATUS
FileMonVolumeDeviceNameToDosName(
								 IN PUNICODE_STRING DeviceName,
								 OUT PUNICODE_STRING DosName
								 )
{
	NTSTATUS status;
	UNICODE_STRING driveLetterName;
	WCHAR c;
	UNICODE_STRING linkTarget;
	WCHAR     TempLetterName[]=L"\\??\\C:";

	DosName->Buffer=NULL;

	RtlInitUnicodeString(&driveLetterName, TempLetterName);

	for (c = 'A'; c <= 'Z'; c++) 
	{
		driveLetterName.Buffer[4] = c;

		status = FileMonQuerySymbolicLink(&driveLetterName, &linkTarget);


		if (!NT_SUCCESS(status)) 
		{
			continue;
		}

		if (RtlEqualUnicodeString(&linkTarget, DeviceName, TRUE)) 
		{
			ExFreePoolWithTag(linkTarget.Buffer,'dsf ');
			break;
		}

		ExFreePoolWithTag(linkTarget.Buffer,'dsf ');
	}

	if (c <= 'Z') 
	{
		DosName->Buffer = ExAllocatePoolWithTag(PagedPool, 3*sizeof(WCHAR),'dsf ');
		if (!DosName->Buffer) 
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DosName->MaximumLength = 6;
		DosName->Length = 4;
		DosName->Buffer[0] = c + (L'a' - L'A');
		DosName->Buffer[1] = ':';
		DosName->Buffer[2] = 0;
		return STATUS_SUCCESS;
	}
	return STATUS_OBJECT_NAME_NOT_FOUND;
}

void RemoveBacklash(wchar_t *szFileName)
{
	if(szFileName[wcslen(szFileName)-1] == L'\\')
		szFileName[wcslen(szFileName)-1] = 0;
}

NTSTATUS
FileMonGetFullPathName(
					   PFLT_FILE_NAME_INFORMATION nameInfo,
					   WCHAR * fullpathname
					   )

{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING dosName;
	WCHAR* wTempName= NULL;

	ntStatus=FileMonVolumeDeviceNameToDosName((PUNICODE_STRING)&nameInfo->Volume,&dosName);
	if(NT_SUCCESS( ntStatus ))
	{
		
		RtlCopyMemory(fullpathname,dosName.Buffer,dosName.Length);

		if (dosName.Buffer)
		{
			ExFreePoolWithTag(dosName.Buffer,'dsf ');
		}

		wTempName=(WCHAR*)ExAllocatePoolWithTag(NonPagedPool,MAXPATHLEN,'dsf ');
		if(wTempName!=NULL)
		{
			RtlZeroMemory(wTempName,MAXPATHLEN);
			RtlCopyMemory(wTempName,nameInfo->ParentDir.Buffer,nameInfo->ParentDir.Length);
			
			wcscat(fullpathname,wTempName);
			
			RtlZeroMemory(wTempName,MAXPATHLEN);
			RtlCopyMemory(wTempName,nameInfo->FinalComponent.Buffer,nameInfo->FinalComponent.Length);
			
			wcscat(fullpathname,wTempName);

			if (wTempName)
			{
				ExFreePoolWithTag(wTempName,'dsf ');
			}

		}

	}else
	{
		ntStatus = STATUS_UNSUCCESSFUL;
	}
	return ntStatus;
}