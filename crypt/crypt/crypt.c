#include "crypt.h"
#include "driver.h"
#include "CryptStrategy.h"

LIST_ENTRY list_head;
KSPIN_LOCK list_lock={0};
KLOCK_QUEUE_HANDLE list_lock_handle;

NTSTATUS ListEntry(__in PUNICODE_STRING file_name,
				__in PFILE_HEAD file_head)
{
	LONG n = 1;
	PMY_LIST node = ExAllocatePoolWithTag( PagedPool,
                                        n*sizeof(MY_LIST),
                                        MEM_TAG );
	LONG len = file_name->Length;
	
	ASSERT(file_name);
	ASSERT(file_head);
	
	if( node == NULL )
		return STATUS_INSUFFICIENT_RESOURCES;
	
	node->file_name.Buffer = (PWCHAR)ExAllocatePoolWithTag(PagedPool, len*sizeof(WCHAR),MEM_TAG); 
	
	if( node->file_name.Buffer == NULL )
		return STATUS_INSUFFICIENT_RESOURCES;
  
	node->file_name.MaximumLength = len*sizeof(WCHAR); 
 
	RtlCopyUnicodeString(&node->file_name, file_name);

	node->file_head.key.key = file_head->key.key;
	node->file_head.cipher_object = file_head->cipher_object;
	node->file_head.cleartext_object = file_head->cleartext_object;
	
	KeAcquireInStackQueuedSpinLock(&list_lock, &list_lock_handle);
	
	InsertHeadList(&list_head, &node->list_entry);
	
	LOG_PRINT(LOGFL_TABLE,("build table:%wZ",file_name));
	
	KeReleaseInStackQueuedSpinLock(&list_lock_handle);
	
	return STATUS_SUCCESS;
}

PFILE_HEAD FindFileHead(__in PUNICODE_STRING file_name)
{
	PLIST_ENTRY p;
	PMY_LIST elem;
	
	for(p=list_head.Flink; p!=&list_head; p=p->Flink)
	{
		
		elem = CONTAINING_RECORD(p, MY_LIST, list_entry);
		if( elem )
		{
			if( RtlCompareUnicodeString(file_name, &elem->file_name, TRUE) == 0 )
			{
				LOG_PRINT(LOGFL_TABLE,("find file:%wZ",&elem->file_name));
				return &elem->file_head;
			}
			else
				continue;
		}
	}
	return NULL;
}

BOOLEAN HaveFileHead(__in PCHAR buffer,
					__in ULONG len)
{
	
	ULONG i = 0;
	ASSERT( buffer );
	ASSERT( len >= FILE_HEAD_LEN );
	for(; i<FILE_HEAD_LEN; i++)
	{
		if( buffer[i] != '0' )
			return FALSE;
	}
	return TRUE;
}


BOOLEAN IsCryptFile(__inout PFLT_CALLBACK_DATA Data,
				   __in PCFLT_RELATED_OBJECTS FltObjects)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	
	if( !FindFileHead(&file_object->FileName) )
	{
		return FALSE;
	}
	else
		return TRUE;
}

NTSTATUS BuildFileTable(__inout PFLT_CALLBACK_DATA Data)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	FILE_HEAD file_head;
	NTSTATUS status = STATUS_SUCCESS;
	
	file_head.key.key=1;
	status = ListEntry(&file_object->FileName, &file_head);
	return status;
}

NTSTATUS AddEncryptFile(__in PUNICODE_STRING file_name,
						__in PVOID buffer,
						__in ULONG Length,
						__in PFILE_OBJECT cipher_object,
						__in PFILE_OBJECT cleartext_object)
{
	FILE_HEAD file_head;
	NTSTATUS status = STATUS_SUCCESS;
	
	file_head.key.key=1;
	file_head.cipher_object = cipher_object;
	file_head.cleartext_object = cleartext_object;
	
	status = ListEntry(file_name, &file_head);
	return status;
}

PCRYPT_KEY GetDecryptKey(__in PFILE_HEAD file_head)
{
	return NULL;
}

PCRYPT_KEY GetEncryptKey(__in PFILE_HEAD file_head)
{
	return NULL;
}

VOID EncryptBuffer(
	__inout PFLT_CALLBACK_DATA Data,
	__in BOOLEAN WriteFileHead,
	__in BOOLEAN Encrypt)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	PFLT_PARAMETERS para = &(iopb->Parameters);
	PCHAR buffer = para->Write.WriteBuffer;
	PFILE_HEAD file_head = FindFileHead(&file_object->FileName);
	CHAR tmp;
	ULONG i = 0;
	
	if( file_head == NULL )
	{
		BuildFileTable(Data);
		file_head = FindFileHead(&file_object->FileName);
	}
	
	//write file head
	if( WriteFileHead )
	{
		LOG_PRINT(LOGFL_WRITE,("write encrypted head\n"));
		for(; i<FILE_HEAD_LEN; i++)
		{
			buffer[i] = '0';
		}
		
	}
	if( Encrypt )
	{
		GetEncryptKey(file_head);
		//encrypt data
		for(; i<para->Write.Length; i++)
		{
			tmp = buffer[i];
			buffer[i] = ((tmp&0xf)<<4)|((tmp&0xf0)>>4);
		}
		LOG_PRINT(LOGFL_WRITE,("data encrypted\n"));
	}
}

BOOLEAN NeedDecrypt(__inout PFLT_CALLBACK_DATA Data)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	PFLT_PARAMETERS para = &(iopb->Parameters);
	PCHAR buffer;
	
	PFILE_HEAD file_head = FindFileHead(&file_object->FileName);
	
	/*if( file_head )
		return TRUE;*/
	
	if (iopb->Parameters.Read.MdlAddress != NULL) 
	{
            //
            //  There is a MDL defined for the original buffer, get a
            //  system address for it so we can copy the data back to it.
            //  We must do this because we don't know what thread context
            //  we are in.
            //

            buffer = MmGetSystemAddressForMdlSafe( iopb->Parameters.Read.MdlAddress,
                                                    NormalPagePriority );

            if (buffer == NULL) 
			{

                LOG_PRINT( LOGFL_ERRORS,
                           ("PostRead:\nFailed to get system address for MDL: %p\n",
                            iopb->Parameters.Read.MdlAddress) );

                //
                //  If we failed to get a SYSTEM address, mark that the read
                //  failed and return.
                //

                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                return FALSE;
            }

    }
	else
	{

            //
            //  If this is a system buffer, just use the given address because
            //      it is valid in all thread contexts.
            //  If this is a FASTIO operation, we can just use the
            //      buffer (inside a try/except) since we know we are in
            //      the correct thread context (you can't pend FASTIO's).
            //

            buffer = iopb->Parameters.Read.ReadBuffer;
    }
	
	if( para->Read.ByteOffset.QuadPart == 0 )
	{
		if( Data->IoStatus.Information >= FILE_HEAD_LEN )
		{
			if( HaveFileHead(buffer, Data->IoStatus.Information) )
			{
				BuildFileTable(Data);
				file_head = FindFileHead(&file_object->FileName);
				if( file_head )
					return TRUE;
			}
		}
	}
	return FALSE;
}

BOOLEAN DecryptBuffer(
	__inout PCHAR buffer,
	__inout PULONG len)
{
	ULONG i = 0;
	if( !DecryptFile(NULL) )
		return TRUE;
	
	GetDecryptKey(NULL);
	
	for(; i<*len; i++)
	{
		buffer[i] = ((buffer[i]&0xf)<<4)|((buffer[i]&0xf0)>>4);
	}
	return TRUE;
}