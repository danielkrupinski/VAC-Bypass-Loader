#include <Windows.h>
#include <ShlObj.h>
#include <TlHelp32.h>

#include "binary.h"

#define ERASE_ENTRY_POINT    TRUE
#define ERASE_PE_HEADER      TRUE

typedef struct {
    PBYTE imageBase;
    HMODULE(WINAPI* loadLibraryA)(PCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
    VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);
} LoaderData;

DWORD WINAPI loadLibrary(LoaderData* loaderData)
{
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(loaderData->imageBase + ((PIMAGE_DOS_HEADER)loaderData->imageBase)->e_lfanew);
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(loaderData->imageBase
        + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD delta = (DWORD)(loaderData->imageBase - ntHeaders->OptionalHeader.ImageBase);
    while (relocation->VirtualAddress) {
        PWORD relocationInfo = (PWORD)(relocation + 1);
        for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++)
            if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
                * (PDWORD)(loaderData->imageBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += delta;

        relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
    }

    PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(loaderData->imageBase
        + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDirectory->Characteristics) {
        PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->FirstThunk);

        HMODULE module = loaderData->loadLibraryA((LPCSTR)loaderData->imageBase + importDirectory->Name);

        if (!module)
            return FALSE;

        while (originalFirstThunk->u1.AddressOfData) {
            DWORD Function = (DWORD)loaderData->getProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->imageBase + originalFirstThunk->u1.AddressOfData))->Name);

            if (!Function)
                return FALSE;

            firstThunk->u1.Function = Function;
            originalFirstThunk++;
            firstThunk++;
        }
        importDirectory++;
    }

    if (ntHeaders->OptionalHeader.AddressOfEntryPoint) {
        DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
            (loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint))
            ((HMODULE)loaderData->imageBase, DLL_PROCESS_ATTACH, NULL);

#if ERASE_ENTRY_POINT
        loaderData->rtlZeroMemory(loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint, 32);
#endif

#if ERASE_PE_HEADER
        loaderData->rtlZeroMemory(loaderData->imageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
#endif
        return result;
    }
    return TRUE;
}

VOID stub(VOID) { }

VOID waitOnModule(DWORD processId, PCWSTR moduleName)
{
    BOOL foundModule = FALSE;

    while (!foundModule) {
        HANDLE moduleSnapshot = INVALID_HANDLE_VALUE;

        while (moduleSnapshot == INVALID_HANDLE_VALUE)
            moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

        MODULEENTRY32W moduleEntry;
        moduleEntry.dwSize = sizeof(moduleEntry);

        if (Module32FirstW(moduleSnapshot, &moduleEntry)) {
            do {
                if (!lstrcmpW(moduleEntry.szModule, moduleName)) {
                    foundModule = TRUE;
                    break;
                }
            } while (Module32NextW(moduleSnapshot, &moduleEntry));
        }
        CloseHandle(moduleSnapshot);
    }
}

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd)
{
    HKEY key = NULL;
    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Valve\\Steam", 0, KEY_QUERY_VALUE, &key)) {
        WCHAR steamPath[MAX_PATH] = { 0 };
        DWORD steamPathSize = MAX_PATH;

        if (!RegQueryValueExW(key, L"InstallPath", NULL, NULL, (LPBYTE)steamPath, &steamPathSize)) {
            lstrcatW(steamPath, L"\\Steam.exe");

            STARTUPINFOW info = { sizeof(info) };
            PROCESS_INFORMATION processInfo;

            if (CreateProcessW(steamPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &info, &processInfo)) {
                waitOnModule(processInfo.dwProcessId, L"Steam.exe");
                SuspendThread(processInfo.hThread);

                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(binary + ((PIMAGE_DOS_HEADER)binary)->e_lfanew);

                PBYTE executableImage = VirtualAllocEx(processInfo.hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                WriteProcessMemory(processInfo.hProcess, executableImage, binary,
                    ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

                PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
                for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
                    WriteProcessMemory(processInfo.hProcess, executableImage + sectionHeaders[i].VirtualAddress,
                        binary + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, NULL);

                LoaderData* loaderMemory = VirtualAllocEx(processInfo.hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READ);

                LoaderData loaderParams;
                loaderParams.imageBase = executableImage;
                loaderParams.loadLibraryA = LoadLibraryA;
                loaderParams.getProcAddress = GetProcAddress;
                loaderParams.rtlZeroMemory = (VOID(WINAPI*)(PVOID, SIZE_T))GetProcAddress(LoadLibraryW(L"ntdll"), "RtlZeroMemory");

                WriteProcessMemory(processInfo.hProcess, loaderMemory, &loaderParams, sizeof(LoaderData),
                    NULL);
                WriteProcessMemory(processInfo.hProcess, loaderMemory + 1, loadLibrary,
                    (DWORD)stub - (DWORD)loadLibrary, NULL);
                HANDLE thread = CreateRemoteThread(processInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(loaderMemory + 1),
                    loaderMemory, 0, NULL);

                ResumeThread(processInfo.hThread);
                WaitForSingleObject(thread, INFINITE);
                VirtualFreeEx(processInfo.hProcess, loaderMemory, 0, MEM_RELEASE);
            }
        }
        RegCloseKey(key);
    }
    return TRUE;
}
