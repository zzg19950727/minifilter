#include "Operation.h"
#include "CryptStrategy.h"
#include "crypt.h"
#include "driver.h"

extern PFLT_FILTER gFilterHandle;
extern NPAGED_LOOKASIDE_LIST Pre2PostContextList;

FLT_PREOP_CALLBACK_STATUS
SwapPreWriteBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	PFLT_PARAMETERS para = &(iopb->Parameters);
	UNICODE_STRING volume_name;
	WCHAR buffer[256];
	
    //PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PVOID newBuf = NULL;
    PMDL newMdl = NULL;
    PVOLUME_CONTEXT volCtx = NULL;
    PPRE_2_POST_CONTEXT p2pCtx;
    PVOID origBuf;
    NTSTATUS status;
    ULONG writeLen;
	ULONG DataLen = iopb->Parameters.Write.Length;
	ULONG offset = 0;
	BOOLEAN WriteFileHead = FALSE;
	BOOLEAN NeedFlush = FALSE;
	BOOLEAN Encrypt = TRUE;
	
	if( !IsMyFile(Data) )
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if( !EncryptFile(NULL) )
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}
	
	if( para->Write.ByteOffset.QuadPart==0 && 
		para->Write.MdlAddress == NULL )
	{
		WriteFileHead = TRUE;
		offset = FILE_HEAD_LEN;
	}
	else if( para->Write.MdlAddress != NULL )
	{
		Encrypt = FALSE;
		//NeedFlush = TRUE;
	}
	
    try
	{
        if (para->Write.Length == 0)
		{

            leave;
        }

        status = FltGetVolumeContext( FltObjects->Filter,
                                      FltObjects->Volume,
                                      &volCtx );

        if (!NT_SUCCESS(status)) 
		{
            leave;
        }

		if( WriteFileHead )
			WriteFileSkipHead(para);
		
		writeLen = iopb->Parameters.Write.Length;
	
        if (FlagOn(IRP_NOCACHE,iopb->IrpFlags)) 
		{
            writeLen = (ULONG)ROUND_TO_SIZE(writeLen,volCtx->SectorSize);
        }

        newBuf = ExAllocatePoolWithTag( PagedPool,
                                        writeLen,
                                        BUFFER_SWAP_TAG );

        if (newBuf == NULL)
		{
            leave;
        }

        if (FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_IRP_OPERATION)) 
		{
            newMdl = IoAllocateMdl( newBuf,
                                    writeLen,
                                    FALSE,
                                    FALSE,
                                    NULL );

            if (newMdl == NULL)
			{
                leave;
            }
            MmBuildMdlForNonPagedPool( newMdl );
        }

        if (iopb->Parameters.Write.MdlAddress != NULL) 
		{

            origBuf = MmGetSystemAddressForMdlSafe( iopb->Parameters.Write.MdlAddress,NormalPagePriority );

            if (origBuf == NULL) 
			{
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                retValue = FLT_PREOP_COMPLETE;
                leave;
            }

        } 
		else 
		{
            origBuf = iopb->Parameters.Write.WriteBuffer;
        }

        try 
		{
            RtlCopyMemory( (PCHAR)newBuf+offset,
                           origBuf,
                           DataLen );
        } 
		except (EXCEPTION_EXECUTE_HANDLER) 
		{
            Data->IoStatus.Status = GetExceptionCode();
            Data->IoStatus.Information = 0;
            retValue = FLT_PREOP_COMPLETE;
            leave;
        }

        iopb->Parameters.Write.WriteBuffer = newBuf;
        iopb->Parameters.Write.MdlAddress = newMdl;
        FltSetCallbackDataDirty( Data );

		p2pCtx = ExAllocateFromNPagedLookasideList( &Pre2PostContextList );

		if (p2pCtx == NULL)
		{
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		*CompletionContext = p2pCtx;

        p2pCtx->SwappedBuffer = newBuf;
        p2pCtx->VolCtx = volCtx;
		p2pCtx->WriteFileHead = WriteFileHead;
		p2pCtx->NeedFlush = NeedFlush;

		EncryptBuffer(Data, WriteFileHead, Encrypt);
        retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    } 
	finally 
	{
        if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK) 
		{

            if (newBuf != NULL) 
			{
                ExFreePool( newBuf );
            }

            if (newMdl != NULL)
			{
                IoFreeMdl( newMdl );
            }

            if (volCtx != NULL) 
			{
                FltReleaseContext( volCtx );
            }
        }
    }

    return retValue;
}

FLT_POSTOP_CALLBACK_STATUS
SwapPostWriteBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	PFLT_PARAMETERS para = &(iopb->Parameters);
	UNICODE_STRING volume_name;
	WCHAR buffer[256];
	
	
    PPRE_2_POST_CONTEXT p2pCtx = (PPRE_2_POST_CONTEXT)CompletionContext;
	
	UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
	
	if( !IsMyFile(Data) )
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	
	if( p2pCtx->WriteFileHead )
	{
		if( NT_SUCCESS(Data->IoStatus.Status) )
			Data->IoStatus.Information -= FILE_HEAD_LEN;
	}
	
	if( p2pCtx->NeedFlush )
	{
		;//ClearCache(Data);
	}
	
    ExFreePool( p2pCtx->SwappedBuffer );
    FltReleaseContext( p2pCtx->VolCtx );

    ExFreeToNPagedLookasideList( &Pre2PostContextList,
                                 p2pCtx );
	
    return FLT_POSTOP_FINISHED_PROCESSING;
}