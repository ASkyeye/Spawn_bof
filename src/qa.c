#include <windows.h>
#include <native.h>

 typedef NTSTATUS (*fnNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

INT WINAPI WinMain(
    HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    LPSTR     lpCmdLine, 
    int       nShowCmd
) {
    PSTR  CmdLine = "cmd.exe /c dir";
    PSTR  SpfCmd  = "cmd.exe /c whoami";

    BOOL  bErrChk = FALSE;
    DWORD BtsRead = 0x00;
    DWORD BtsWtn  = 0x00;
    DWORD Retln   = 0x00;
    LONG  Status  = 0x00;
    PPEB  Peb     = { 0 };

    HANDLE hStdPipeRead  = NULL;
    HANDLE hStdPipeWrite = NULL;

    SECURITY_ATTRIBUTES SecAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };
    STARTUPINFOA        Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    PROCESS_BASIC_INFORMATION    Pbi    = { 0 };
    PRTL_USER_PROCESS_PARAMETERS Params = { 0 };

    ZeroMemory( &Si,  sizeof( STARTUPINFOA ) );
    ZeroMemory( &Pi,  sizeof( PROCESS_INFORMATION ) );
    ZeroMemory( &Pbi, sizeof( PROCESS_BASIC_INFORMATION ) );
    ZeroMemory( &Params, sizeof( RTL_USER_PROCESS_PARAMETERS ) );

    fnNtQueryInformationProcess NtQueryInfoProc = GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQueryInformationProcess" );

    bErrChk = CreatePipe( &hStdPipeRead, &hStdPipeWrite, &SecAttr, 0 );

    Si.cb          = sizeof( STARTUPINFOA );
    Si.dwFlags     = STARTF_USESTDHANDLES;
    Si.wShowWindow = SW_HIDE;
    Si.hStdInput   = NULL;
    Si.hStdOutput  = hStdPipeWrite;
    Si.hStdError   = hStdPipeWrite;

    bErrChk = CreateProcessA( NULL, CmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &Si, &Pi );
    if ( !bErrChk ) goto ExitRoutine;

    printf( "[+] Created Process...\n\t> Command line: %s\n\t> Process ID: %d\n\t> Main Thread ID: %d\n", CmdLine, Pi.dwProcessId, Pi.dwThreadId );

    Status = NtQueryInfoProc( Pi.hProcess, ProcessBasicInformation, &Pbi, sizeof( PROCESS_BASIC_INFORMATION ), &Retln );
    if ( Status != 0 ) goto ExitRoutine;

    Peb = (PPEB)LocalAlloc( LPTR, sizeof( PEB ) );

    bErrChk = ReadProcessMemory( Pi.hProcess, Pbi.PebBaseAddress, &Peb, sizeof( PEB ), &BtsRead );
    if ( !bErrChk ) goto ExitRoutine;

    bErrChk = ReadProcessMemory( Pi.hProcess, Peb->ProcessParameters, &Params, sizeof( RTL_USER_PROCESS_PARAMETERS ) + 0xFF, &BtsRead );
    if ( !bErrChk ) goto ExitRoutine;

    bErrChk = WriteProcessMemory( Pi.hProcess, ( PVOID )Params->CommandLine.Buffer, ( PVOID )SpfCmd, ( DWORD )( lstrlenW( CmdLine ) * sizeof( WCHAR ) + 1 ), &BtsWtn );
    if ( !bErrChk ) goto ExitRoutine;

    ResumeThread( Pi.hThread );

    PBYTE BufferOut       = NULL;
    CHAR  BufferCnt[1025] = { 0 };
    DWORD BufferRead      = 0x00;
    DWORD BufferSize      = 0x00;

    CloseHandle( hStdPipeWrite );

    BufferOut = ( PBYTE )LocalAlloc( LPTR, 1024 ); 

    if ( BufferOut == NULL ) {
        printf( "Memory allocation failed.\n" );
        goto ExitRoutine;

    }

    while ( TRUE ) {
        bErrChk = ReadFile( hStdPipeRead, BufferCnt, sizeof( BufferCnt ) - 1, &BufferRead, NULL );
        
        if ( !bErrChk || BufferRead == 0 ) {
            break;
        }

        PBYTE TempBuffer = ( PBYTE )LocalReAlloc( BufferOut, BufferSize + BufferRead + 1, LMEM_MOVEABLE );
        if ( TempBuffer == NULL ) {
            printf( "Memory reallocation failed.\n" );
            goto ExitRoutine;
        }

        BufferOut = TempBuffer;

        memcpy( BufferOut + BufferSize, BufferCnt, BufferRead );
        BufferSize += BufferRead;
        BufferOut[ BufferSize ] = '\0';
    }

    printf( "[+] Output of process\n%s", BufferOut );

ExitRoutine:
    if ( hStdPipeRead  )  CloseHandle( hStdPipeRead );
    if ( Pi.hProcess   )  CloseHandle( Pi.hProcess );
    if ( Pi.hThread    )  CloseHandle( Pi.hThread );
    if ( BufferOut     )  LocalFree( BufferOut );
    if ( Peb           )  LocalFree( Peb );
    if ( Params        )  LocalFree( Params );

    return 0;
}
