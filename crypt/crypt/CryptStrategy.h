#ifndef CRYPTSTRATEGY_H
#define CRYPTSTRATEGY_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

enum _OPERATION{READ,WRITE};
typedef enum _OPERATION OPERATION;

typedef struct _MY_CTX
{
	PFILE_OBJECT   TargetFileObject;
	FLT_PARAMETERS Parameters;
	OPERATION operation;
}MY_CTX,*PMY_CTX;

VOID CurProcNameInit();

BOOLEAN IsNotepad();

BOOLEAN IsNotepadPlus();

BOOLEAN IsWinOffice();

BOOLEAN IsMyFile(
	__in PFLT_CALLBACK_DATA Data);

BOOLEAN IsWinOfficeFile();

BOOLEAN IsTmpFile();

BOOLEAN EncryptFile(
	__in PMY_CTX ctx);
	
BOOLEAN DecryptFile(
	__in PMY_CTX ctx);

	
#endif	//CRYPTSTRATEGY_H