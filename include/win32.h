#include <windows.h>
#include <structs.h>

#define STATUS_SUCCESS	    0x00000000
#define NT_SUCCESS(STATUS)	(((NTSTATUS)(STATUS)) >= STATUS_SUCCESS)

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x100000000000
#endif

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
DECLSPEC_IMPORT BOOL  KERNEL32$CloseHandle( HANDLE Handle );

DECLSPEC_IMPORT LPVOID KERNEL32$HeapAlloc( _In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes );
DECLSPEC_IMPORT BOOL   KERNEL32$HeapFree( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem );
DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalAlloc( UINT uFlags, SIZE_T uBytes );
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalFree( HLOCAL hMem );
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalReAlloc( HLOCAL hMem, SIZE_T uBytes, UINT uFlags );

DECLSPEC_IMPORT BOOL KERNEL32$CreatePipe( PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize );
DECLSPEC_IMPORT BOOL KERNEL32$ReadFile( HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped );

DECLSPEC_IMPORT HANDLE KERNEL32$OpenProcess( DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId );
DECLSPEC_IMPORT BOOL   KERNEL32$CreateProcessA( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );
DECLSPEC_IMPORT BOOL   KERNEL32$InitializeProcThreadAttributeList( LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize );
DECLSPEC_IMPORT BOOL   KERNEL32$UpdateProcThreadAttribute( LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize );
DECLSPEC_IMPORT VOID   KERNEL32$DeleteProcThreadAttributeList( LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList );
