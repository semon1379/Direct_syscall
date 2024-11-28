#include "util.h"
#include "syscall_header.h"

DWORD wNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
DWORD wNtCreateThreadEx;
DWORD wNtWaitForSingleObject;

const char* patterns[38] = {
    "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile", "NtDeleteFile",
    "NtQueryInformationFile", "NtSetInformationFile",

    // ���μ��� �� ������ ���� �Լ�
    "NtOpenProcess", "NtTerminateProcess", "NtSuspendProcess", "NtResumeProcess",
    "NtCreateThreadEx", "NtOpenThread", "NtTerminateThread", "NtSuspendThread",
    "NtResumeThread",

    // �޸� ���� �Լ�
    "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtReadVirtualMemory",
    "NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtQueryVirtualMemory",

    // ������Ʈ�� ���� �Լ�
    "NtCreateKey", "NtOpenKey", "NtDeleteKey", "NtSetValueKey", "NtQueryValueKey",
    "NtEnumerateKey",

    // ����ȭ ���� �Լ�
    "NtCreateEvent", "NtOpenEvent", "NtWaitForSingleObject",
    "NtSignalAndWaitForSingleObject",

    // �ý��� ���� ���� �Լ�
    "NtQuerySystemInformation", "NtSetSystemInformation",
    "NtQueryPerformanceCounter",

    // ��Ÿ
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
    

    if (instruction[3] == 0xB8) { // x86-64: mov eax, imm32
        return instruction[4]; // syscall_number
    }
    return 0; // syscall_number�� Ȯ�ε��� ����
}

void get_ssn() {
    
    
    size_t patternCount = sizeof(patterns) / sizeof(patterns[0]);

    printf("System Call Table (Nt/Zw functions):\n");
    printf("------------------------------------\n");

    for (size_t i = 0; i < patternCount; i++) {
        const char* functionName = patterns[i];

        unsigned char syscallNumber = GetSyscallNumber(functionName);
        if (syscallNumber != 0) {
            ssn[i] = syscallNumber; // functionName�� syscallNumber index ��Ī
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
