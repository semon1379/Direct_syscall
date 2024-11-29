#ifndef _SYSCALL_HEADER_H  
#define _SYSCALL_HEADER_H

#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

    extern DWORD wNtAllocateVirtualMemory;
    extern DWORD wNtWriteVirtualMemory;
    extern DWORD wNtCreateThreadEx;
    extern DWORD wNtWaitForSingleObject;
    extern DWORD wNtCreateFile;
    extern DWORD wNtWriteFile;
    extern DWORD wNtDeleteFile;

    typedef long NTSTATUS;
    typedef NTSTATUS* PNTSTATUS;

    extern const char* patterns[38];
    extern int ssn[38];

    #define FILE_SUPERSEDE                 0x00000000
    #define FILE_OPEN                      0x00000001
    #define FILE_CREATE                    0x00000002
    #define FILE_OPEN_IF                   0x00000003
    #define FILE_OVERWRITE                 0x00000004
    #define FILE_OVERWRITE_IF              0x00000005
    #define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020

    #define STATUS_SUCCESS ((NTSTATUS)0x00000000)

    typedef VOID(NTAPI* PIO_APC_ROUTINE) (
        IN PVOID ApcContext,
        IN PIO_STATUS_BLOCK IoStatusBlock,
        IN ULONG Reserved
    );

    typedef VOID(NTAPI* RtlInitUnicodeString_t)(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
    );

    extern NTSTATUS NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    extern NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PULONG NumberOfBytesWritten
    );

    extern NTSTATUS NtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID lpStartAddress,
        PVOID lpParameter,
        ULONG Flags,
        SIZE_T StackZeroBits,
        SIZE_T SizeOfStackCommit,
        SIZE_T SizeOfStackReserve,
        PVOID lpBytesBuffer
    );

    extern NTSTATUS NtWaitForSingleObject(
        HANDLE Handle,
        BOOLEAN Alertable,
        PLARGE_INTEGER Timeout
    );

    extern NTSTATUS NtCreateFile(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength
    );

    extern NTSTATUS NtWriteFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID Buffer,
        ULONG Length,
        PLARGE_INTEGER ByteOffset,
        PULONG Key
    );

    extern NTSTATUS NtDeleteFile(
        POBJECT_ATTRIBUTES ObjectAttributes
    );

#ifdef __cplusplus 
}
#endif

#endif
