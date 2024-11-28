#include "util.h"
#include "syscall_header.h"

DWORD wNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
DWORD wNtCreateThreadEx;
DWORD wNtWaitForSingleObject;

/*  테스트 환경에서의 함수 구성
4C:8BD1                  | mov r10,rcx
B8 31000000              | mov eax,[syscallNumber]
F60425 0803FE7F 01       | test byte ptr ds:[7FFE0308],1
75 03                    | jne ntdll.7FF94AABD125
0F05                     | syscall
C3                       | ret
*/

const char* patterns[38] = {
    "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile", "NtDeleteFile",
    "NtQueryInformationFile", "NtSetInformationFile",

    // 프로세스 및 스레드 관련 함수
    "NtOpenProcess", "NtTerminateProcess", "NtSuspendProcess", "NtResumeProcess",
    "NtCreateThreadEx", "NtOpenThread", "NtTerminateThread", "NtSuspendThread",
    "NtResumeThread",

    // 메모리 관련 함수
    "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtReadVirtualMemory",
    "NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtQueryVirtualMemory",

    // 레지스트리 관련 함수
    "NtCreateKey", "NtOpenKey", "NtDeleteKey", "NtSetValueKey", "NtQueryValueKey",
    "NtEnumerateKey",

    // 동기화 관련 함수
    "NtCreateEvent", "NtOpenEvent", "NtWaitForSingleObject",
    "NtSignalAndWaitForSingleObject",

    // 시스템 정보 관련 함수
    "NtQuerySystemInformation", "NtSetSystemInformation",
    "NtQueryPerformanceCounter",

    // 기타
    "NtDelayExecution", "NtRaiseException", "NtClose"
};

int ssn[38] = { 0, };

unsigned char GetSyscallNumber(const char* functionName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("Failed to load ntdll.dll\n");
        return 0;
    }

    FARPROC func = GetProcAddress(ntdll, functionName);
    if (!func) {
        return 0;
    }
    unsigned char* instruction = (unsigned char*)func;

    size_t instructionCount = sizeof(instruction) / sizeof(instruction[0]);
    
    for (size_t i = 0; i < instructionCount; i++) {
        if (instruction[i] == 0xB8) { // x86-64: mov eax, imm32
            return instruction[i + 1]; // syscall_number
        }
    }
    
    return 0; // syscall_number가 확인되지 않음
}

void get_ssn() {
    
    
    size_t patternCount = sizeof(patterns) / sizeof(patterns[0]);

    printf("System Call Table (Nt/Zw functions):\n");
    printf("------------------------------------\n");

    for (size_t i = 0; i < patternCount; i++) {
        const char* functionName = patterns[i];

        unsigned char syscallNumber = GetSyscallNumber(functionName);
        if (syscallNumber != 0) {
            ssn[i] = syscallNumber; // functionName과 syscallNumber index 매칭
            printf("%s: 0x%02X\n", functionName, syscallNumber);
        }
        else {
            printf("%s: Not Found or No System Call Number\n", functionName);
        }
        if (functionName == "NtWaitForSingleObject") {
            wNtWaitForSingleObject = syscallNumber;
        } else if (functionName == "NtAllocateVirtualMemory") {
            wNtAllocateVirtualMemory = syscallNumber;
        } else if (functionName == "NtWriteVirtualMemory") {
            wNtWriteVirtualMemory = syscallNumber;
        } else if (functionName == "NtCreateThreadEx") {
            wNtCreateThreadEx = syscallNumber;
        }
    }
}
