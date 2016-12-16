#ifndef __WHITE_NAME_H__
#define __WHITE_NAME_H__
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <WinDef.h>
typedef struct _WHITE_NAME_LIST
{
	LIST_ENTRY listNode;
	WCHAR xxName[296];
	WCHAR xxFileType[296];

}WHITE_NAME_LIST,*PWHITE_NAME_LIST;

VOID InitWhiteProcNameListAndLock();
VOID AddNameToWhiteNameList(PWSTR xxName, PWSTR xxFileType);
VOID DelNameFromWhiteNameList(PWSTR xxName, PWSTR xxFileType);
BOOL IsNameInWhiteNameList(PWSTR xxName, PWSTR xxFileType);
BOOL RtlPatternMatch(WCHAR * pat, WCHAR * str);
VOID ClearWhiteNameList();
BOOL SearchIsProtect(PWSTR DirPath,PWSTR FileName);

#endif 