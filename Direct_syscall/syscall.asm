EXTERN wNtAllocateVirtualMemory:DWORD               
EXTERN wNtWriteVirtualMemory:DWORD                  
EXTERN wNtCreateThreadEx:DWORD                      
EXTERN wNtWaitForSingleObject:DWORD                 

.CODE  ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                                    
    mov eax, wNtAllocateVirtualMemory               
    syscall                                         
    ret                                             
NtAllocateVirtualMemory ENDP                        


; Similar procedures for NtWriteVirtualMemory syscalls
NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtWriteVirtualMemory
    syscall
    ret
NtWriteVirtualMemory ENDP


; Similar procedures for NtCreateThreadEx syscalls
NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, wNtCreateThreadEx
    syscall
    ret
NtCreateThreadEx ENDP


; Similar procedures for NtWaitForSingleObject syscalls
NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, wNtWaitForSingleObject
    syscall
    ret
NtWaitForSingleObject ENDP

END  ; End of the module