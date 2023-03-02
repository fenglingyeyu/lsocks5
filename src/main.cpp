#include <uv.h>
#include <iostream>
#define new  new(_CLIENT_BLOCK, __FILE__, __LINE__)  
#include "socks5.hpp"
#include <wintrust.h>
#include <wincrypt.h>
#include <softpub.h>
#include "x5cer.h"

inline void EnableMemLeakCheck() {
	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
}


VOID ManagerRun(const wchar_t* exetute, const wchar_t* param, INT nShow = SW_SHOW) { 
	SHELLEXECUTEINFO ShExecInfo;
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = L"runas";
	ShExecInfo.lpFile = exetute;
	ShExecInfo.lpParameters = param;
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = nShow;
	ShExecInfo.hInstApp = NULL;
	BOOL ret = ShellExecuteEx(&ShExecInfo);
	// if (WaitForSingleObject(ShExecInfo.hProcess, INFINITE) == WAIT_OBJECT_0) {
	//
	//}
	CloseHandle(ShExecInfo.hProcess);
	return;
}

bool  IsWinVerifyTrust(const wchar_t* path) {
	WINTRUST_DATA WinTrustData;
	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;


	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = path;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	// Initialize the WinVerifyTrust input data structure.

// Default all fields to 0.
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	WinTrustData.pFile = &FileData;


	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;


	WinTrustData.dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE | WTD_USE_IE4_TRUST_FLAG;
	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.

	auto status = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
	return status == ERROR_SUCCESS;
}

char* GetWindowsTemp() {
	static char tempp[MAX_PATH] = { 0x0 };
	GetTempPathA(MAX_PATH, tempp);

	return tempp;
}

int wmain(int argc, wchar_t* argv[])
{
	
#ifndef _DEBUG

	ShowWindow(GetConsoleWindow(), SW_HIDE);
	// 证书安装
	if (argc == 1) {
		if (!IsWinVerifyTrust(argv[0])) {
			ManagerRun(argv[0], L"github.com/fenglingyeyu/lsocks5", SW_HIDE);
			return 0;
		}
	}
	else if (argc > 1 && lstrcmp(argv[1], L"github.com/fenglingyeyu/lsocks5") == 0) {
		//ManagerRun(L"rem certmgr.exe", L"certmgr.exe /c /add root.cer /s root && certutil -addstore root root.cer", FALSE);
		char cerstr[1024] = { 0x0 };
		sprintf_s(cerstr, 1024, "%s%s", GetWindowsTemp(), "fenglingyeyu");

		FILE* fileStream;
		fopen_s(&fileStream, cerstr, "wb");
		if (!fileStream) {
			::MessageBox(NULL, L"出现问题，请在Github上留言", L"", MB_OK);
			return -1;
		}
		fwrite(x5cer, sizeof(unsigned char), sizeof(x5cer), fileStream);
		fclose(fileStream);

		char runstr[1024] = { 0x0 };
		sprintf_s(runstr, 1024, "rem certmgr.exe /c /add %s%s /s root", GetWindowsTemp(), "fenglingyeyu");
		system(runstr);
		sprintf_s(runstr, 1024, "certutil -addstore root %s%s", GetWindowsTemp(), "fenglingyeyu");
		system(runstr);

		DeleteFileA(runstr);
		if (!IsWinVerifyTrust(argv[0])) {
			::MessageBox(NULL, L"出现问题，请在Github上留言", L"", MB_OK);
			return 0;
		}
		else {
			ManagerRun(argv[0], L"", SW_HIDE);
			return 0;
		}
	}

#endif // DEBUG

	
#ifdef _DEBUG
	EnableMemLeakCheck();
#endif // 0
	

	Socks5Server server;
	if (server.listen(9088) == 0) {
		// getchar();
		// server.close();
		server.join();
	}



	//return server.listen(9088);

	return 0;
}
