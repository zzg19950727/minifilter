#include "CryptStrategy.h"
#include "crypt.h"
#include "driver.h"

static size_t proc_name_offset = 0;

extern BOOLEAN service_enable;

VOID CurProcNameInit()
{
	ULONG i;
	PEPROCESS curproc;
	curproc = PsGetCurrentProcess();
	
	for(i=0; i<3*4*1024; i++)
	{
		if( !strncmp("System", (PCHAR)curproc+i, strlen("System")) )
		{
			proc_name_offset = i;
			break;
		}
	}
}

ULONG CurProcName(
	__inout PUNICODE_STRING name)
{
	PEPROCESS curproc;
	ULONG i, need_len;
	ANSI_STRING ansi_name;
	if( proc_name_offset == 0 )
		return 0;
	
	curproc = PsGetCurrentProcess();
	
	RtlInitAnsiString(&ansi_name, ((PCHAR)curproc+proc_name_offset) );
	need_len = RtlAnsiStringToUnicodeSize(&ansi_name);
	
	if(need_len > name->MaximumLength)
	{
		return 0;
	}
	
	RtlAnsiStringToUnicodeString(name, &ansi_name, FALSE);
	return need_len;
}

BOOLEAN IsNotepad()
{
	WCHAR buffer[256]={0};
	UNICODE_STRING proc_name,note_name;
	ULONG length;
	
	RtlInitEmptyUnicodeString(&proc_name, buffer, 256*sizeof(WCHAR));
	length = CurProcName(&proc_name);
	
	RtlInitUnicodeString(&note_name, L"notepad.exe");
	if(RtlCompareUnicodeString(&note_name, &proc_name, TRUE) == 0 )
		return TRUE;
	else
		return FALSE;
}

BOOLEAN IsNotepadPlus()
{
	WCHAR buffer[256]={0};
	UNICODE_STRING proc_name,note_name;
	ULONG length;
	
	RtlInitEmptyUnicodeString(&proc_name, buffer, 256*sizeof(WCHAR));
	length = CurProcName(&proc_name);
	
	RtlInitUnicodeString(&note_name, L"notepad++.exe");
	if(RtlCompareUnicodeString(&note_name, &proc_name, TRUE) == 0 )
		return TRUE;
	else
		return FALSE;
}

BOOLEAN IsWinOffice()
{
	
	WCHAR buffer[256]={0};
	UNICODE_STRING proc_name;
	UNICODE_STRING word = RTL_CONSTANT_STRING(L"WINWORD.EXE");
	UNICODE_STRING excel = RTL_CONSTANT_STRING(L"EXCEL.EXE");
	UNICODE_STRING point = RTL_CONSTANT_STRING(L"POWERPNT.EXE");
	ULONG length;
	
	RtlInitEmptyUnicodeString(&proc_name, buffer, 256*sizeof(WCHAR));
	length = CurProcName(&proc_name);
	
	if(RtlCompareUnicodeString(&word, &proc_name, TRUE) == 0 )
		return TRUE;
	if(RtlCompareUnicodeString(&excel, &proc_name, TRUE) == 0 )
		return TRUE;
	if(RtlCompareUnicodeString(&point, &proc_name, TRUE) == 0 )
		return TRUE;
	return FALSE;
}

BOOLEAN IsTestFile(
	__in PFLT_CALLBACK_DATA Data)
{
	NTSTATUS status;
	const char*exe = "TEST.TXT";
	UNICODE_STRING name;
	ANSI_STRING ansi_name;
	char buff1[200];
	WCHAR buff2[200];
	RtlInitEmptyUnicodeString(&name, buff2, 200*sizeof(WCHAR));
	RtlInitEmptyAnsiString(&ansi_name, buff1, 200*sizeof(char));

	if( Data->Iopb->TargetFileObject->FileName.Length )
	{
		RtlUpcaseUnicodeString(&name, &Data->Iopb->TargetFileObject->FileName, FALSE);
		RtlUnicodeStringToAnsiString(&ansi_name, &name, FALSE);
		
		if( strstr(ansi_name.Buffer, exe) > 0 )
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN IsWinOfficeFile(
	__in PFLT_CALLBACK_DATA Data)
{
	NTSTATUS status;
	const char* word = ".DOC";
	const char* excel = ".XLS";
	const char* point = ".PPT";
	UNICODE_STRING name;
	ANSI_STRING ansi_name;
	char buff1[200];
	WCHAR buff2[200];
	RtlInitEmptyUnicodeString(&name, buff2, 200*sizeof(WCHAR));
	RtlInitEmptyAnsiString(&ansi_name, buff1, 200*sizeof(char));
	
	if( Data->Iopb->TargetFileObject->FileName.Length )
	{
		RtlUpcaseUnicodeString(&name, &Data->Iopb->TargetFileObject->FileName, FALSE);
		RtlUnicodeStringToAnsiString(&ansi_name, &name, FALSE);
		
		if( strstr(ansi_name.Buffer, word) > 0 )
		{
			return TRUE;
		}
		if( strstr(ansi_name.Buffer, excel) > 0 )
		{
			return TRUE;
		}
		if( strstr(ansi_name.Buffer,point) > 0 )
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN IsTmpFile(
	__in PFLT_CALLBACK_DATA Data)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION name_info;
	const char*exe = ".TMP";
	UNICODE_STRING name;
	ANSI_STRING ansi_name;
	char buff1[200];
	WCHAR buff2[200];
	RtlInitEmptyUnicodeString(&name, buff2, 200*sizeof(WCHAR));
	RtlInitEmptyAnsiString(&ansi_name, buff1, 200*sizeof(char));
	
	if( Data->Iopb->TargetFileObject->FileName.Length )
	{
		RtlUpcaseUnicodeString(&name, &Data->Iopb->TargetFileObject->FileName, FALSE);
		RtlUnicodeStringToAnsiString(&ansi_name, &name, FALSE);
		
		if( strstr(ansi_name.Buffer, exe) > 0 )
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN IsMyFile(
	__in PFLT_CALLBACK_DATA Data)
{
	BOOLEAN status;
	
	if(!service_enable)
		return FALSE;

	status = IsTestFile(Data);
	if( status == TRUE )
		return status;
	
	if( IsWinOffice() && (IsWinOfficeFile(Data) || IsTmpFile(Data) ) )
	{
		status = TRUE;
	}
	else
		status = FALSE;
	
	return status;	
}

BOOLEAN EncryptFile(
	__in PMY_CTX ctx)
{
	if(!service_enable)
		return FALSE;

	if( IsNotepadPlus() )
		return TRUE;
	else
		return FALSE;
}
	
BOOLEAN DecryptFile(
	__in PMY_CTX ctx)
{
	if(!service_enable)
		return FALSE;

	if( IsNotepadPlus() )
		return TRUE;
	else
		return FALSE;
}