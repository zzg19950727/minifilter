#ifndef CRYPT_H
#define CRYPT_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#define FILE_HEAD_LEN		100
#define MEM_TAG 'MyMe'

typedef struct _CRYPT_KEY
{
	ULONG key;
}CRYPT_KEY, *PCRYPT_KEY;

typedef struct _FILE_HEAD
{
	CRYPT_KEY key;
	PFILE_OBJECT cipher_object;
	PFILE_OBJECT cleartext_object;
}FILE_HEAD,*PFILE_HEAD;

typedef struct _MY_LIST
{
	LIST_ENTRY list_entry;
	UNICODE_STRING file_name;
	FILE_HEAD file_head;
	
}MY_LIST, *PMY_LIST;

NTSTATUS ListEntry(__in PUNICODE_STRING file_name,
				__in PFILE_HEAD file_head);

PFILE_HEAD FindFileHead(__in PUNICODE_STRING file_name);

BOOLEAN HaveFileHead(__in PCHAR buffer,
					__in ULONG len);

BOOLEAN IsCryptFile(__inout PFLT_CALLBACK_DATA Data,
				   __in PCFLT_RELATED_OBJECTS FltObjects);
				   
NTSTATUS BuildFileTable(__inout PFLT_CALLBACK_DATA Data);

NTSTATUS AddEncryptFile(__in PUNICODE_STRING file_name,
						__in PVOID buffer,
						__in ULONG Length,
						__in PFILE_OBJECT cipher_object,
						__in PFILE_OBJECT cleartext_object);

PCRYPT_KEY GetDecryptKey(__in PFILE_HEAD file_head);

PCRYPT_KEY GetEncryptKey(__in PFILE_HEAD file_head);

BOOLEAN NeedDecrypt(__inout PFLT_CALLBACK_DATA Data);

VOID EncryptBuffer(
	__inout PFLT_CALLBACK_DATA Data,
	__in BOOLEAN WriteFileHead,
	__in BOOLEAN Encrypt);
	
BOOLEAN DecryptBuffer(
	__inout PCHAR buffer,
	__inout PULONG len);

#endif	//CRYPT_H