#include "Operation.h"
#include "CryptStrategy.h"
#include "crypt.h"
#include "driver.h"

extern PFLT_FILTER gFilterHandle;

extern NPAGED_LOOKASIDE_LIST Pre2PostContextList;


FLT_PREOP_CALLBACK_STATUS
PreCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{	

	if( IsMyFile(Data) )
	{
		CommonCreateFile(Data, FltObjects);
		
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	if(DecryptFile(NULL))
		ClearCache( file_object );
	return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN 
CommonCreateFile(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects
    )
{
	NTSTATUS status;
	LARGE_INTEGER ByteOffset;
	ULONG Length = FILE_HEAD_LEN;
	CHAR buffer[FILE_HEAD_LEN];
	ULONG RetLen;
	UNICODE_STRING file_path;
	BOOLEAN RetStatus = FALSE;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	
	try
	{
		GetFullPath(Data, FltObjects, &file_path);
		
		if( FindFileHead(&file_path ) )
			leave;

		ByteOffset.QuadPart = 0;
		status = FltReadFile(FltObjects->Instance,
							file_object,
							&ByteOffset,
							Length,
							buffer,
							FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
							&RetLen,
							NULL,
							NULL);
		
		if( !NT_SUCCESS(status) )
			leave;
		
		if( RetLen != FILE_HEAD_LEN )
			leave;
		
		if( !HaveFileHead(buffer, RetLen) )
			leave;

		RetStatus = TRUE;
	}
	finally
	{
		FreePath( &file_path );
		return RetStatus;
	}
}

FLT_PREOP_CALLBACK_STATUS
PreClose(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostClose(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	return FLT_POSTOP_FINISHED_PROCESSING;
}
	
FLT_PREOP_CALLBACK_STATUS
PreQueryInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	if( !IsMyFile(Data) )
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	else
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostQueryInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	PFLT_PARAMETERS para = &(iopb->Parameters);
	PUCHAR buffer = para->QueryFileInformation.InfoBuffer;
    switch(para->QueryFileInformation.FileInformationClass)
    {
    case FileAllInformation:
        {
            PFILE_ALL_INFORMATION all_infor = (PFILE_ALL_INFORMATION)buffer;
            if(Data->IoStatus.Information >= 
                sizeof(FILE_BASIC_INFORMATION) + 
                sizeof(FILE_STANDARD_INFORMATION))
            {
                //ASSERT(all_infor->StandardInformation.EndOfFile.QuadPart >= FILE_HEAD_LEN);
				if(all_infor->StandardInformation.EndOfFile.QuadPart >= FILE_HEAD_LEN){
				all_infor->StandardInformation.EndOfFile.QuadPart -= FILE_HEAD_LEN;
                all_infor->StandardInformation.AllocationSize.QuadPart -= FILE_HEAD_LEN;
				}
                if(Data->IoStatus.Information >= 
                    sizeof(FILE_BASIC_INFORMATION) + 
                    sizeof(FILE_STANDARD_INFORMATION) +
                    sizeof(FILE_INTERNAL_INFORMATION) +
                    sizeof(FILE_EA_INFORMATION) +
                    sizeof(FILE_ACCESS_INFORMATION) +
                    sizeof(FILE_POSITION_INFORMATION))
                {
                    if(all_infor->PositionInformation.CurrentByteOffset.QuadPart >= FILE_HEAD_LEN)
                        all_infor->PositionInformation.CurrentByteOffset.QuadPart -= FILE_HEAD_LEN;
                }
            }
            break;
        }
    case FileAllocationInformation:
        {
		    PFILE_ALLOCATION_INFORMATION alloc_infor = 
                (PFILE_ALLOCATION_INFORMATION)buffer;
            //ASSERT(alloc_infor->AllocationSize.QuadPart >= FILE_HEAD_LEN);
			if(alloc_infor->AllocationSize.QuadPart >= FILE_HEAD_LEN)
		    alloc_infor->AllocationSize.QuadPart -= FILE_HEAD_LEN;     
            break;
        }
    case FileValidDataLengthInformation:
        {
		    PFILE_VALID_DATA_LENGTH_INFORMATION valid_length = 
                (PFILE_VALID_DATA_LENGTH_INFORMATION)buffer;
            //ASSERT(valid_length->ValidDataLength.QuadPart >= FILE_HEAD_LEN);
			if(valid_length->ValidDataLength.QuadPart >= FILE_HEAD_LEN)
		    valid_length->ValidDataLength.QuadPart -= FILE_HEAD_LEN;
            break;
        }
    case FileStandardInformation:
        {
            PFILE_STANDARD_INFORMATION stand_infor = (PFILE_STANDARD_INFORMATION)buffer;
            //ASSERT(stand_infor->AllocationSize.QuadPart >= FILE_HEAD_LEN);
			if(stand_infor->EndOfFile.QuadPart >= FILE_HEAD_LEN){
            stand_infor->AllocationSize.QuadPart -= FILE_HEAD_LEN;            
            stand_infor->EndOfFile.QuadPart -= FILE_HEAD_LEN;}
            break;
        }
    case FileEndOfFileInformation:
        {
		    PFILE_END_OF_FILE_INFORMATION end_infor = 
                (PFILE_END_OF_FILE_INFORMATION)buffer;
            //ASSERT(end_infor->EndOfFile.QuadPart >= FILE_HEAD_LEN);
			if( end_infor->EndOfFile.QuadPart >= FILE_HEAD_LEN )
		    end_infor->EndOfFile.QuadPart -= FILE_HEAD_LEN;
            break;
        }
	case FilePositionInformation:
		{
			PFILE_POSITION_INFORMATION PositionInformation =
				(PFILE_POSITION_INFORMATION)buffer; 
            if(PositionInformation->CurrentByteOffset.QuadPart > FILE_HEAD_LEN)
			    PositionInformation->CurrentByteOffset.QuadPart -= FILE_HEAD_LEN;
			break;
		}
    default:
        ;
    };
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PreSetInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PFILE_OBJECT file_object = iopb->TargetFileObject;
	PFLT_PARAMETERS para = &(iopb->Parameters);
	PUCHAR buffer = para->SetFileInformation.InfoBuffer;
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if( !IsMyFile(Data) )
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	
    switch(para->SetFileInformation.FileInformationClass)
    {
    case FileAllocationInformation:
        {
		    PFILE_ALLOCATION_INFORMATION alloc_infor = 
                (PFILE_ALLOCATION_INFORMATION)buffer;
		    alloc_infor->AllocationSize.QuadPart += FILE_HEAD_LEN;        
            break;
        }
    case FileEndOfFileInformation:
        {
		    PFILE_END_OF_FILE_INFORMATION end_infor = 
                (PFILE_END_OF_FILE_INFORMATION)buffer;
			//if(end_infor->EndOfFile.QuadPart != 0)
		    end_infor->EndOfFile.QuadPart += FILE_HEAD_LEN;
            break;
        }
    case FileValidDataLengthInformation:
        {
		    PFILE_VALID_DATA_LENGTH_INFORMATION valid_length = 
                (PFILE_VALID_DATA_LENGTH_INFORMATION)buffer;
		    valid_length->ValidDataLength.QuadPart += FILE_HEAD_LEN;
            break;
        }/*
	case FilePositionInformation:
		{
			PFILE_POSITION_INFORMATION position_infor = 
				(PFILE_POSITION_INFORMATION)buffer;
			position_infor->CurrentByteOffset.QuadPart += FILE_HEAD_LEN;
		}*/
	case FileStandardInformation:
		((PFILE_STANDARD_INFORMATION)buffer)->EndOfFile.QuadPart += FILE_HEAD_LEN;
		break;
	case FileAllInformation:
	{
		((PFILE_ALL_INFORMATION)buffer)->PositionInformation.CurrentByteOffset.QuadPart += FILE_HEAD_LEN;
		((PFILE_ALL_INFORMATION)buffer)->StandardInformation.EndOfFile.QuadPart += FILE_HEAD_LEN;
		break;
	}
    default:
        ;
    };
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostSetInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PreNetworkOpen(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( CompletionContext );
	
	if( IsMyFile(Data) ) 
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostNetworkOpen(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( CompletionContext );
	UNREFERENCED_PARAMETER( Flags );

	return FLT_POSTOP_FINISHED_PROCESSING;
}