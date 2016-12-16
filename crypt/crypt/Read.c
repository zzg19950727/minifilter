#include "CryptStrategy.h"
#include "Operation.h"
#include "crypt.h"
#include "driver.h"

extern PFLT_FILTER gFilterHandle;

extern NPAGED_LOOKASIDE_LIST Pre2PostContextList;

FLT_PREOP_CALLBACK_STATUS
SwapPreReadBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT ori_object = iopb->TargetFileObject;
	PFILE_OBJECT file_object;
	BOOLEAN decrypt = TRUE;
	PFLT_PARAMETERS para = &(iopb->Parameters);
    PPRE_2_POST_CONTEXT p2pCtx;
	
    FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
    ULONG readLen = iopb->Parameters.Read.Length;
	PFILE_HEAD file_head;
	UNICODE_STRING file_path;
	
	GetFullPath(Data, FltObjects, &file_path);
	file_head = FindFileHead(&file_path);
	FreePath(&file_path);
	
	if( file_head == NULL )
		return retValue;
	
    try 
	{
        if (readLen == 0) 
            leave;
		
		if( !DecryptFile(NULL) )
		{
			para->Read.ByteOffset.QuadPart += FILE_HEAD_LEN;
			file_object = file_head->cipher_object;
			decrypt = FALSE;
		}
		
		p2pCtx = (PPRE_2_POST_CONTEXT)ExAllocateFromNPagedLookasideList( &Pre2PostContextList );

		if (p2pCtx == NULL) 
		{
				leave;
		}
		*CompletionContext = p2pCtx;

        p2pCtx->file_object = ori_object;
		
		p2pCtx->decrypt = decrypt;
		
        retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    } 
	finally 
	{
		return retValue;
    }
}


FLT_POSTOP_CALLBACK_STATUS
SwapPostReadBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	PFLT_PARAMETERS para = &(iopb->Parameters);
	
	PCHAR origBuf;
	PPRE_2_POST_CONTEXT p2pCtx = (PPRE_2_POST_CONTEXT)CompletionContext;
    BOOLEAN cleanupAllocatedBuffer = FALSE;
    FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;

    ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));
	
	try 
	{
        if (!NT_SUCCESS(Data->IoStatus.Status) ||
            (Data->IoStatus.Information == 0)) 
		{
            leave;
        }
		
		if( !p2pCtx->decrypt )
		{
			leave;
		}
		
		if(!FlagOn(iopb->IrpFlags,IRP_PAGING_IO))
		{
			leave;
		}

        if (iopb->Parameters.Read.MdlAddress != NULL) 
		{
            origBuf = (PCHAR)MmGetSystemAddressForMdlSafe( iopb->Parameters.Read.MdlAddress,NormalPagePriority );

            if (origBuf == NULL) 
			{
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                leave;
            }

        }
		else
		{
            origBuf = (PCHAR)iopb->Parameters.Read.ReadBuffer;
        }
		
		if( !DecryptBuffer(origBuf, &Data->IoStatus.Information) )
		{
            Data->IoStatus.Information = 0;
            leave;
		}
	}
	finally
	{
		if (cleanupAllocatedBuffer) 
		{
            ExFreeToNPagedLookasideList( &Pre2PostContextList,p2pCtx );
        }
	}
    return retValue;
}