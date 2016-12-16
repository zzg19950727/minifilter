#ifndef DRIVER_H
#define DRIVER_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

/*************************************************************************
    Pool Tags
*************************************************************************/

#define BUFFER_SWAP_TAG     'bdBS'
#define CONTEXT_TAG         'xcBS'
#define NAME_TAG            'mnBS'
#define PRE_2_POST_TAG      'ppBS'

#define MIN_SECTOR_SIZE 0x200
#define MY_NAME 4
#define MAXPATHLEN		1024

/*************************************************************************
    Debug tracing information
*************************************************************************/

//
//  Definitions to display log messages.  The registry DWORD entry:
//  "hklm\system\CurrentControlSet\Services\Swapbuffers\DebugFlags" defines
//  the default state of these logging flags
//

#define LOGFL_ERRORS    0x00000001  // if set, display error messages
#define LOGFL_READ      0x00000002  // if set, display READ operation info
#define LOGFL_WRITE     0x00000004  // if set, display WRITE operation info
#define LOGFL_DIRCTRL   0x00000008  // if set, display DIRCTRL operation info
#define LOGFL_VOLCTX    0x00000010  // if set, display VOLCTX operation info
#define LOGFL_CREATE	0x00000020
#define LOGFL_CLOSE		0x00000040
#define LOGFL_TABLE		0x00000080
#define LOGFL_TEST		0x00000100

ULONG LoggingFlags;
#define LOG_PRINT( _logFlag, _string )                              \
    (FlagOn(LoggingFlags,(_logFlag)) ?                              \
        DbgPrint _string  :                                         \
        ((int)0))
/*************************************************************************
    Local structures
*************************************************************************/

//
//  This is a volume context, one of these are attached to each volume
//  we monitor.  This is used to get a "DOS" name for debug display.
//

typedef struct _VOLUME_CONTEXT {

    //
    //  Holds the name to display
    //

    UNICODE_STRING Name;

    //
    //  Holds the sector size for this volume.
    //

    ULONG SectorSize;

} VOLUME_CONTEXT, *PVOLUME_CONTEXT;

//
//  This is a context structure that is used to pass state from our
//  pre-operation callback to our post-operation callback.
//

typedef struct _PRE_2_POST_CONTEXT {

    //
    //  Pointer to our volume context structure.  We always get the context
    //  in the preOperation path because you can not safely get it at DPC
    //  level.  We then release it in the postOperation path.  It is safe
    //  to release contexts at DPC level.
    //

    PVOLUME_CONTEXT VolCtx;

    //
    //  Since the post-operation parameters always receive the "original"
    //  parameters passed to the operation, we need to pass our new destination
    //  buffer to our post operation routine so we can free it.
    //

    PVOID SwappedBuffer;
	
	BOOLEAN WriteFileHead;
	
	BOOLEAN NeedFlush;
	
	PFILE_OBJECT file_object;
	
	BOOLEAN decrypt;
} PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;

VOID GetVolumeName(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__inout PUNICODE_STRING name);

VOID
GetFullPath(__inout PFLT_CALLBACK_DATA Data,
			__in PCFLT_RELATED_OBJECTS FltObjects,
			__inout PUNICODE_STRING path);
			
VOID
GetTmpPath(__inout PUNICODE_STRING path);

			
VOID FreePath(PUNICODE_STRING path);
			
VOID WriteFileSkipHead(PFLT_PARAMETERS para);

VOID ClearCache(__in PFILE_OBJECT pFileObject);

	
#endif	//DRIVER_H