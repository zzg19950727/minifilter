// user.cpp : Defines the entry point for the console application.
//
#include "common.h"
#include <stdio.h>
#include <Windows.h>
#include <fltuser.h>
#include <FltUserStructures.h>

#pragma comment(lib, "FltLib.lib")

#define MINISPY_NAME      L"MiniSpy"

int main(void)
{
	int c = 1;
	while (c)
	{
		scanf("%d", &c);
		switch (c)
		{
		case 1:
			start_service();
			break;
		case 2:
			stop_service();
			break;
		case 3:
			MyAddProtectPath(L"c:", L".txt");
			break;
		case 4:
			MyDelProtectPath(L"c:", L".txt");
			break;
		}
	}
	return 0;
}

void start_service()
{
	HANDLE port = INVALID_HANDLE_VALUE;
	DWORD result;
	INPUT_BUFFER input;
	HRESULT hResult = S_OK;

	hResult = FilterConnectCommunicationPort(MINISPY_PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&port);

	if (IS_ERROR(hResult))
	{
		goto Exit;
	}

	ZeroMemory(&input, sizeof(INPUT_BUFFER));

	input.command = START_SERVICE;
	wcscpy(input.protectedPath, L"");
	wcscpy(input.fileType, L"");

	FilterSendMessage(port,
		&input,
		sizeof(INPUT_BUFFER),
		NULL,
		0,
		&result);

Exit:
	if (INVALID_HANDLE_VALUE != port)
	{
		CloseHandle(port);
	}
}

void stop_service()
{
	HANDLE port = INVALID_HANDLE_VALUE;
	DWORD result;
	INPUT_BUFFER input;
	HRESULT hResult = S_OK;

	hResult = FilterConnectCommunicationPort(MINISPY_PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&port);

	if (IS_ERROR(hResult))
	{
		goto Exit;
	}

	ZeroMemory(&input, sizeof(INPUT_BUFFER));

	input.command = STOP_SERVICE;
	wcscpy(input.protectedPath, L"");
	wcscpy(input.fileType, L"");

	FilterSendMessage(port,
		&input,
		sizeof(INPUT_BUFFER),
		NULL,
		0,
		&result);

Exit:
	if (INVALID_HANDLE_VALUE != port)
	{
		CloseHandle(port);
	}
}

VOID MyAddProtectPath(WCHAR *path, WCHAR *fileType)
{
	HANDLE port = INVALID_HANDLE_VALUE;
	DWORD result;
	INPUT_BUFFER input;
	HRESULT hResult = S_OK;

	hResult = FilterConnectCommunicationPort(MINISPY_PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&port);

	if (IS_ERROR(hResult))
	{
		goto Exit;
	}

	ZeroMemory(&input, sizeof(INPUT_BUFFER));

	input.command = ADD_PROTECTED_PATH;
	wcscpy(input.protectedPath, path);
	wcscpy(input.fileType, fileType);


	//发送 ADD_PROTECTED_PATH命令，准备和驱动层进行通信
	FilterSendMessage(port,
		&input,
		sizeof(INPUT_BUFFER),
		NULL,
		0,
		&result);

Exit:
	if (INVALID_HANDLE_VALUE != port)
	{
		CloseHandle(port);
	}
}


VOID MyDelProtectPath(WCHAR *path, WCHAR *fileType)
{
	HANDLE port = INVALID_HANDLE_VALUE;
	DWORD result;
	INPUT_BUFFER input;
	HRESULT hResult = S_OK;

	hResult = FilterConnectCommunicationPort(MINISPY_PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&port);

	if (IS_ERROR(hResult))
	{
		goto Exit;
	}

	ZeroMemory(&input, sizeof(INPUT_BUFFER));

	input.command = DEL_PROTECTED_PATH;
	wcscpy(input.protectedPath, path);
	wcscpy(input.fileType, fileType);


	//发送 DEL_PROTECTED_PATH命令，准备和驱动层进行通信
	FilterSendMessage(port,
		&input,
		sizeof(INPUT_BUFFER),
		NULL,
		0,
		&result);

Exit:
	if (INVALID_HANDLE_VALUE != port)
	{
		CloseHandle(port);
	}
}