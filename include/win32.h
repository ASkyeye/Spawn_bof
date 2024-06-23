#include <windows.h>
#include <structs.h>

#define STATUS_SUCCESS	    0x00000000
#define NT_SUCCESS(STATUS)	(((NTSTATUS)(STATUS)) >= STATUS_SUCCESS)
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON         (0x00000001 << 44)

#define C_PTR( x )   ( ( LPVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )

#define DEREF_64( x ) (PDWORD64) ( x )
#define DEREF_32( x ) (PDWORD)   ( x )
#define DEREF_16( x ) (PWORD)    ( x )
#define DEREF_8( x )  (PBYTE)    ( x )

PVOID  MemSet(void* Destination, int Value, size_t Size);
VOID   MemZero( _Inout_ PVOID Destination, _In_ SIZE_T Size);
PVOID  MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);
void   InitUnicodeString(_Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer);
SIZE_T StringLengthW(_In_ LPCWSTR String);
INT    StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2);

DECLSPEC_IMPORT DWORD KERNEL32$GetLastError();

DECLSPEC_IMPORT BOOL KERNEL32$CreatePipe(
    PHANDLE               hReadPipe,
    PHANDLE               hWritePipe,
    LPSECURITY_ATTRIBUTES lpPipeAttributes,
    DWORD                 nSize
);

DECLSPEC_IMPORT NTSTATUS NTDLL$NtCreateUserProcess(
    OUT         PHANDLE ProcessHandle,
    OUT         PHANDLE ThreadHandle,
    IN          ACCESS_MASK ProcessDesiredAccess,
    IN          ACCESS_MASK ThreadDesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ProcessObjectAttributes,
    IN OPTIONAL POBJECT_ATTRIBUTES ThreadObjectAttributes,
    IN ULONG    ProcessFlags,                                    // PROCESS_CREATE_FLAGS_*
    IN ULONG    ThreadFlags,                                     // THREAD_CREATE_FLAGS_*
    IN OPTIONAL PRTL_USER_PROCESS_PARAMETERS ProcessParameters,                     
    IN OUT      PPS_CREATE_INFO CreateInfo,
    IN          PPS_ATTRIBUTE_LIST AttributeList
);

DECLSPEC_IMPORT NTSTATUS NTDLL$RtlCreateProcessParametersEx(
    OUT 	PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    IN 		PUNICODE_STRING ImagePathName,
    IN OPTIONAL PUNICODE_STRING DllPath,         // set to NULL
    IN OPTIONAL PUNICODE_STRING CurrentDirectory,
    IN OPTIONAL PUNICODE_STRING CommandLine,
    IN OPTIONAL PVOID Environment,              // set to NULL
    IN OPTIONAL PUNICODE_STRING WindowTitle,    // set to NULL
    IN OPTIONAL PUNICODE_STRING DesktopInfo,    // set to NULL
    IN OPTIONAL PUNICODE_STRING ShellInfo,      // set to NULL
    IN OPTIONAL PUNICODE_STRING RuntimeData,    // set to NULL
    IN ULONG Flags 
);

DECLSPEC_IMPORT LPVOID KERNEL32$HeapAlloc(
    _In_ HANDLE hHeap,
    _In_ DWORD  dwFlags,
    _In_ SIZE_T dwBytes
);

DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();

DECLSPEC_IMPORT NTSTATUS NTDLL$NtClose(
    HANDLE Handle
);

DECLSPEC_IMPORT HLOCAL KERNEL32$LocalAlloc(
    UINT   uFlags,
    SIZE_T uBytes
);

DECLSPEC_IMPORT HLOCAL KERNEL32$LocalFree(
    HLOCAL hMem
);

DECLSPEC_IMPORT HLOCAL KERNEL32$LocalReAlloc(
    HLOCAL hMem,
    SIZE_T                 uBytes,
    UINT                   uFlags
);

DECLSPEC_IMPORT BOOL KERNEL32$ReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

DECLSPEC_IMPORT NTSTATUS NTDLL$NtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

// NtClose
// RtlAllocateHeap