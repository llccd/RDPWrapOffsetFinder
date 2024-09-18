#include <iostream>
#include <windows.h>
#include <Dbghelp.h>
#include <Zydis/Zydis.h>

typedef struct {
    WORD             wLength;
    WORD             wValueLength;
    WORD             wType;
    WCHAR            szKey[16];
    WORD             Padding1;
    VS_FIXEDFILEINFO Value;
    WORD             Padding2;
    WORD             Children;
} VS_VERSIONINFO, *PVS_VERSIONINFO;

void LocalOnlyPatch(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target);

void DefPolicyPatch(ZydisDecoder* decoder, size_t RVA, size_t base);

int SingleUserPatch(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target, size_t target2);

int main(int argc, char** argv)
{
    auto hProcess = GetCurrentProcess();
    char szTermsrv[MAX_PATH + 1];
    SymSetOptions(SYMOPT_DEBUG | SYMOPT_PUBLICS_ONLY);
    LPCWSTR symPath = NULL;
    GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", NULL, 0);
    if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) symPath = L"cache*;srv*https://msdl.microsoft.com/download/symbols";
    if (!SymInitializeW(hProcess, symPath, FALSE)) return -1;
    if (argc >= 2) lstrcpyA(szTermsrv, argv[1]);
    else lstrcpyA(szTermsrv + GetSystemDirectoryA(szTermsrv, sizeof(szTermsrv) / sizeof(char)), "\\termsrv.dll");
#ifndef _WIN64
    PVOID OldValue;
    Wow64DisableWow64FsRedirection(&OldValue);
#endif // _WIN64
    auto hMod = LoadLibraryExA(szTermsrv, NULL, LOAD_LIBRARY_AS_DATAFILE);
#ifndef _WIN64
    Wow64RevertWow64FsRedirection(OldValue);
#endif // _WIN64
    if (!hMod) return -2;
    auto base = (size_t)hMod & ~3;
    auto pDos = (PIMAGE_DOS_HEADER)(base);
    auto pNT = (PIMAGE_NT_HEADERS64)(base + pDos->e_lfanew);
    auto pSection = IMAGE_FIRST_SECTION(pNT);
    base += (size_t)pSection->PointerToRawData - pSection->VirtualAddress;

    size_t ImageBase;
    DWORD SizeOfImage;
    const char* arch = "x64";
    ZydisDecoder decoder;
    if (pNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ImageBase = (size_t)pNT->OptionalHeader.ImageBase;
        SizeOfImage = pNT->OptionalHeader.SizeOfImage;
    }
    else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
        arch = "x86";
        ImageBase = ((PIMAGE_NT_HEADERS32)pNT)->OptionalHeader.ImageBase;
        SizeOfImage = ((PIMAGE_NT_HEADERS32)pNT)->OptionalHeader.SizeOfImage;
    }
    
    SYMSRV_INDEX_INFO Info = { sizeof(SYMSRV_INDEX_INFO) };
#ifndef _WIN64
    Wow64DisableWow64FsRedirection(&OldValue);
#endif // _WIN64
    if (!SymSrvGetFileIndexInfo(szTermsrv, &Info, 0)) return -6;
#ifndef _WIN64
    Wow64RevertWow64FsRedirection(OldValue);
#endif // _WIN64
    if (!SymFindFileInPath(hProcess, NULL, Info.pdbfile, &Info.guid, Info.age, 0, SSRVOPT_GUIDPTR, (PSTR)&szTermsrv, NULL, NULL)) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) puts("Symbol not found");
        return -7;
    }
    if (!SymLoadModuleEx(hProcess, NULL, szTermsrv, NULL, ImageBase, SizeOfImage, NULL, 0)) return -3;

    auto hResInfo = FindResourceW(hMod, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(16));
    if (!hResInfo) return -4;
    auto hResData = (PVS_VERSIONINFO)LoadResource(hMod, hResInfo);
    if (!hResData) return -5;

    SYMBOL_INFOW symbol;
    symbol.SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol.MaxNameLen = 0;

    printf("[%hu.%hu.%hu.%hu]\n", HIWORD(hResData->Value.dwFileVersionMS), LOWORD(hResData->Value.dwFileVersionMS),
        HIWORD(hResData->Value.dwFileVersionLS), LOWORD(hResData->Value.dwFileVersionLS));

    size_t VerifyVersion_addr = -1;
    if (SymFromNameW(hProcess, L"__imp_VerifyVersionInfoW", &symbol) || SymFromNameW(hProcess, L"__imp__VerifyVersionInfoW@16", &symbol))
        VerifyVersion_addr = (size_t)(symbol.Address - symbol.ModBase);

    if (decoder.stack_width == ZYDIS_STACK_WIDTH_32) VerifyVersion_addr += ImageBase;

    SymSetOptions(SYMOPT_DEBUG | SYMOPT_UNDNAME);
    if (SymFromNameW(hProcess, L"memset", &symbol) || SymFromNameW(hProcess, L"_memset", &symbol))
    {
        auto target = (size_t)(symbol.Address - symbol.ModBase);
        if (SymFromNameW(hProcess, L"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled", &symbol) &&
            SingleUserPatch(&decoder, symbol.Address - symbol.ModBase, base, target, VerifyVersion_addr));
        else if (SymFromNameW(hProcess, L"CUtils::IsSingleSessionPerUser", &symbol))
            if(!SingleUserPatch(&decoder, (size_t)(symbol.Address - symbol.ModBase), base, target, VerifyVersion_addr))
                puts("ERROR: SingleUserPatch not found");
    }

    if (SymFromNameW(hProcess, L"CDefPolicy::Query", &symbol))
        DefPolicyPatch(&decoder, (size_t)(symbol.Address - symbol.ModBase), base);
    else puts("ERROR: CDefPolicy_Query not found");

    if (hResData->Value.dwFileVersionMS <= 0x00060001) return 0;

    if (hResData->Value.dwFileVersionMS == 0x00060002)
    {
        if (SymFromNameW(hProcess, L"SLGetWindowsInformationDWORDWrapper", &symbol))
            _printf_p("SLPolicyInternal.%1$s=1\n"
                "SLPolicyOffset.%1$s=%2$llX\n"
                "SLPolicyFunc.%1$s=New_Win8SL\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: SLGetWindowsInformationDWORDWrapper not found");
        return 0;
    }

    if (SymFromNameW(hProcess, L"CEnforcementCore::GetInstanceOfTSLicense", &symbol))
    {
        auto addr = (size_t)(symbol.Address - symbol.ModBase);
        if (SymFromNameW(hProcess, L"CSLQuery::IsLicenseTypeLocalOnly", &symbol))
            LocalOnlyPatch(&decoder, addr, base, (size_t)(symbol.Address - symbol.ModBase));
        else puts("ERROR: IsLicenseTypeLocalOnly not found");
    } else puts("ERROR: GetInstanceOfTSLicense not found");

    if (SymFromNameW(hProcess, L"CSLQuery::Initialize", &symbol))
    {
        _printf_p("SLInitHook.%1$s=1\n"
            "SLInitOffset.%1$s=%2$llX\n"
            "SLInitFunc.%1$s=New_CSLQuery_Initialize\n", arch, symbol.Address - symbol.ModBase);

        printf("\n[%hu.%hu.%hu.%hu-SLInit]\n", HIWORD(hResData->Value.dwFileVersionMS), LOWORD(hResData->Value.dwFileVersionMS),
            HIWORD(hResData->Value.dwFileVersionLS), LOWORD(hResData->Value.dwFileVersionLS));

        if (SymFromNameW(hProcess, L"CSLQuery::bServerSku", &symbol))
            printf("bServerSku.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bServerSku not found");

        if (SymFromNameW(hProcess, L"CSLQuery::bRemoteConnAllowed", &symbol))
            printf("bRemoteConnAllowed.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bRemoteConnAllowed not found");

        if (SymFromNameW(hProcess, L"CSLQuery::bFUSEnabled", &symbol))
            printf("bFUSEnabled.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bFUSEnabled not found");

        if (SymFromNameW(hProcess, L"CSLQuery::bAppServerAllowed", &symbol))
            printf("bAppServerAllowed.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bAppServerAllowed not found");

        if (SymFromNameW(hProcess, L"CSLQuery::bMultimonAllowed", &symbol))
            printf("bMultimonAllowed.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bMultimonAllowed not found");

        if (SymFromNameW(hProcess, L"CSLQuery::lMaxUserSessions", &symbol))
            printf("lMaxUserSessions.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: lMaxUserSessions not found");

        if (SymFromNameW(hProcess, L"CSLQuery::ulMaxDebugSessions", &symbol))
            printf("ulMaxDebugSessions.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: ulMaxDebugSessions not found");

        if (SymFromNameW(hProcess, L"CSLQuery::bInitialized", &symbol))
            printf("bInitialized.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bInitialized not found");
    } else puts("ERROR: CSLQuery_Initialize not found");
    return 0;
}
