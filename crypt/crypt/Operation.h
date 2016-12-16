#ifndef OPERATION_H
#define OPERATION_H

#include "driver.h"
#include "crypt.h"

FLT_PREOP_CALLBACK_STATUS
SwapPreReadBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
SwapPostReadBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_POSTOP_CALLBACK_STATUS
SwapPostReadBuffersWhenSafe (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );
	
VOID ReadFileEncrypted(__inout PFLT_CALLBACK_DATA Data,
					__in PCFLT_RELATED_OBJECTS FltObjects,
					__in PFILE_HEAD file_head);

VOID ReadFileDecrypted(__inout PFLT_CALLBACK_DATA Data,
					__in PCFLT_RELATED_OBJECTS FltObjects,
					__in PFILE_HEAD file_head);
					

FLT_PREOP_CALLBACK_STATUS
SwapPreDirCtrlBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
SwapPostDirCtrlBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
SwapPreWriteBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
SwapPostWriteBuffers(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

VOID
ReadDriverParameters (
    __in PUNICODE_STRING RegistryPath
    );
	
FLT_PREOP_CALLBACK_STATUS
PreCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
PostCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );
	
BOOLEAN 
CommonCreateFile(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects
    );
	
FLT_PREOP_CALLBACK_STATUS
PreClose(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
PostClose(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );
	
FLT_PREOP_CALLBACK_STATUS
PreQueryInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
PostQueryInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PreSetInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
PostSetInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );
	
FLT_PREOP_CALLBACK_STATUS
PreNetworkOpen(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
PostNetworkOpen(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

NTSTATUS
SpyConnect(
		   __in PFLT_PORT ClientPort,
		   __in PVOID ServerPortCookie,
		   __in_bcount(SizeOfContext) PVOID ConnectionContext,
		   __in ULONG SizeOfContext,
		   __deref_out_opt PVOID *ConnectionCookie
		   );

VOID
SpyDisconnect(
			  __in_opt PVOID ConnectionCookie
			  );

NTSTATUS
SpyMessage (
			__in PVOID ConnectionCookie,
			__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
			__in ULONG InputBufferSize,
			__out_bcount_part_opt(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
			__in ULONG OutputBufferSize,
			__out PULONG ReturnOutputBufferLength
			);

NTSTATUS
FileMonGetFullPathName(
					   PFLT_FILE_NAME_INFORMATION nameInfo,
					   WCHAR * fullpathname
					   );

void RemoveBacklash(wchar_t *szFileName);

#endif	//OPERATION_H