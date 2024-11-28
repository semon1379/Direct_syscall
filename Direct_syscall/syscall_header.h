#ifndef _SYSCALL_HEADER_H  
#define _SYSCALL_HEADER_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

    extern DWORD wNtAllocateVirtualMemory;
    extern DWORD wNtWriteVirtualMemory;
    extern DWORD wNtCreateThreadEx;
    extern DWORD wNtWaitForSingleObject;

	typedef long NTSTATUS;
	typedef NTSTATUS* PNTSTATUS;

	extern const char* patterns[38];

    extern int ssn[38];

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

#ifdef __cplusplus 
}
#endif

#endif