#include "stdafx.h";
#include "detours.h"

// MRS.exe Addresses
#define EncryptAddress			0x401120
#define DecryptAddress			0x4010F0

// Typedef Function
typedef void(*pEncrypt)(char* pData, int nSize);
typedef void(*pDecrypt)(char* pData, int nSize);

// Pointing Function
pEncrypt pEnc = (pEncrypt)(EncryptAddress);
pDecrypt pDec = (pDecrypt)(DecryptAddress);

// Encryption Keys
char key[18] = 
{ 
	15, -81, 42, 3, -123, 66, -109, 103, -46, -36, -94, 64, -115, 113, -103, -9, -65, -103 
};

// Encryption/Decryption Detour Function
void Xor(char* pData, int nSize)
{
	if (!pData) {
		return;
	}

	BYTE b;

	for (int i = 0; i < nSize; ++i) {
		char xor = key[i % 18];
		b = *pData;
		b ^= xor;
		*pData = b;
		pData++;
	}
}

// Hook DLL
__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			{
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());

				DetourAttach(&(PVOID&)pEnc, Xor);
				DetourAttach(&(PVOID&)pDec, Xor);

				DetourTransactionCommit();
			}
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

