#include <windows.h>
#include <winnt.h>

#include <beacon.h>
#include <win32.h>

#define RUN      "run"
#define PPID     "ppid"
#define ARGUE    "argue"
#define BLOCKDLL "blockdlls"

SIZE_T StringLengthW(_In_ LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
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

void InitUnicodeString(_Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer)
{
    if ((UsStruct->Buffer = (PWSTR)Buffer))
    {
        unsigned int Length = StringLengthW(Buffer) * sizeof(WCHAR);
        if (Length > 0xfffc)
            Length = 0xfffc;

        UsStruct->Length = Length;
        UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
    }
    else UsStruct->Length = UsStruct->MaximumLength = 0;
}

PVOID MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

VOID MemZero( _Inout_ PVOID Destination, _In_ SIZE_T Size)
{
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

PVOID MemSet(void* Destination, int Value, size_t Size)
{
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}

void go(_In_ char* args, _In_ int argc)
{
    datap Parser     = { 0 };
    PSTR  Handle     = NULL;
    BOOL  Result     = FALSE;
    PSTR  Command    = NULL;
    DWORD CommandLen = 0x00;
    PSTR  TargetProc = NULL;
    DWORD TargetLen  = 0x00;
    PSTR  CurDir     = NULL;
    DWORD CurDirLen  = 0x00;
    DWORD PPid       = 0x00;
    BOOL        BlockDlls    = FALSE;

    const PCHAR PPidKey = "ppidkeyvalue";
    const PCHAR BlockDllsKey = "blockdllskeyvalue";

    BeaconDataParse( &Parser, args, argc );
    
    Handle = BeaconDataExtract( &Parser, NULL );

    if ( StringCompareA( Handle, PPID ) == 0 ) 
    {
        BeaconRemoveValue( PPidKey );
        PPid = BeaconDataInt( &Parser );
        BeaconAddValue( PPidKey, &PPid );
        BeaconPrintf(CALLBACK_OUTPUT, "[+] PPid set to %d\n", PPid);
    }
    else if ( StringCompareA( Handle, BLOCKDLL ) == 0 )
    {
        BeaconRemoveValue( BlockDllsKey );
        BlockDlls = BeaconDataShort( &Parser );
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Block Dlls is True");
        
    } 
    else if ( StringCompareA( Handle, RUN ) == 0 ) 
    {
        Command    = BeaconDataExtract(&Parser, &CommandLen);
        PPid       = (DWORD)BeaconGetValue( PPidKey );
        BlockDlls  = BeaconDataInt(&Parser);

        BeaconPrintf(
            CALLBACK_OUTPUT,
            "[+] Parsed Args:\n"
            "   - Command Line: %ls\n"
            "   - PPid: %d\n",
            //"   - BlockDlls: %d\n",
            Command, PPid, BlockDlls
        );
        /*
        if ( !Spawn( Command, 696, BlockDlls, NULL, NULL ) ) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Spawn execution failed!");
            return;
        }
        */
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Spawn execution succeeded!");
    } 
    else 
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Unknown handle command: %s\n", Handle);
    }

    return;
}

BOOL Spawn(
    _In_      PSTR   Command,
    _In_      DWORD  PPid,
    _In_      BOOL   BlockDlls,
    _Out_opt_ HANDLE *hProc,
    _Out_opt_ HANDLE *hThr
)
{

    return TRUE;
}