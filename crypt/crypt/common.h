#ifndef __COMMON_H__
#define __COMMON_H__

#define MINISPY_PORT_NAME                   L"\\MiniSpyPort"

#define _CMD_PATH 296


typedef enum _MY_COMMAND 
{
	ADD_PROTECTED_PATH,
	DEL_PROTECTED_PATH,
	START_SERVICE,
	STOP_SERVICE
} MY_COMMAND;

typedef struct _INPUT_BUFFER
{
	MY_COMMAND command;
	WCHAR protectedPath[_CMD_PATH];
	WCHAR fileType[_CMD_PATH];
}INPUT_BUFFER, *PINPUT_BUFFER;

#endif