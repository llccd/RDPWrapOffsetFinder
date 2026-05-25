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

bool SLPolicyCP(ZydisDecoder* decoder, size_t RVA, size_t base) {
    ZyanUSize length = 128;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    auto IP = RVA + base;

    if (decoder->stack_width == ZYDIS_STACK_WIDTH_32)
        while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
        {
            IP += instruction.length;
            length -= instruction.length;

            if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[1].mem.base == ZYDIS_REGISTER_EBP &&
                operands[1].mem.disp.value > 0 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                return true;

            if (instruction.mnemonic == ZYDIS_MNEMONIC_TEST) break;
        }
    return false;
}

int main()
{
    auto hProcess = GetCurrentProcess();
    WCHAR szTermsrv[MAX_PATH + 1];
    SymSetOptions(SYMOPT_DEBUG | SYMOPT_PUBLICS_ONLY);
    LPCWSTR symPath = NULL;
    GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", NULL, 0);
    if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) symPath = L"cache*;srv*https://msdl.microsoft.com/download/symbols";
    if (!SymInitializeW(hProcess, symPath, FALSE)) ExitProcess(-1);
    int argc;
    const auto current_cmdline = GetCommandLineW();
    const auto argv = CommandLineToArgvW(current_cmdline, &argc);
    if (!argv) ExitProcess(-8);
    if (argc >= 2) lstrcpyW(szTermsrv, argv[1]);
    else lstrcpyW(szTermsrv + GetSystemDirectoryW(szTermsrv, sizeof(szTermsrv) / sizeof(WCHAR)), L"\\termsrv.dll");
    SYMSRV_INDEX_INFOW Info = { sizeof(SYMSRV_INDEX_INFOW) };
#ifndef _WIN64
    auto wow64func = (BOOLEAN(WINAPI*)(BOOLEAN)) GetProcAddress(GetModuleHandleA("kernel32.dll"), "Wow64EnableWow64FsRedirection");
    if (wow64func) (*wow64func)(FALSE);
#endif // _WIN64
    if (!SymSrvGetFileIndexInfoW(szTermsrv, &Info, 0)) ExitProcess(-6);
    auto hMod = LoadLibraryExW(szTermsrv, NULL, LOAD_LIBRARY_AS_DATAFILE);
#ifndef _WIN64
    if (wow64func) (*wow64func)(TRUE);
#endif // _WIN64
    if (!hMod) ExitProcess(-2);
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
    
    if (!SymFindFileInPathW(hProcess, NULL, Info.pdbfile, &Info.guid, Info.age, 0, SSRVOPT_GUIDPTR, (PWSTR)&szTermsrv, NULL, NULL)) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) puts("Symbol not found");
        ExitProcess(-7);
    }
    if (!SymLoadModuleExW(hProcess, NULL, szTermsrv, NULL, ImageBase, SizeOfImage, NULL, 0)) ExitProcess(-3);

    auto hResInfo = FindResourceW(hMod, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(16));
    if (!hResInfo) ExitProcess(-4);
    auto hResData = (PVS_VERSIONINFO)LoadResource(hMod, hResInfo);
    if (!hResData) ExitProcess(-5);

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
            SingleUserPatch(&decoder, (size_t)(symbol.Address - symbol.ModBase), base, target, VerifyVersion_addr));
        else if (SymFromNameW(hProcess, L"CUtils::IsSingleSessionPerUser", &symbol))
            if(!SingleUserPatch(&decoder, (size_t)(symbol.Address - symbol.ModBase), base, target, VerifyVersion_addr))
                puts("ERROR: SingleUserPatch not found");
    }

    if (SymFromNameW(hProcess, L"CDefPolicy::Query", &symbol))
        DefPolicyPatch(&decoder, (size_t)(symbol.Address - symbol.ModBase), base);
    else puts("ERROR: CDefPolicy_Query not found");

    if (hResData->Value.dwFileVersionMS <= 0x00060001) ExitProcess(0);

    if (hResData->Value.dwFileVersionMS == 0x00060002)
    {
        if (SymFromNameW(hProcess, L"SLGetWindowsInformationDWORDWrapper", &symbol)) {
            auto addr = (size_t)(symbol.Address - symbol.ModBase);

            printf(decoder.stack_width == ZYDIS_STACK_WIDTH_64
                ? "SLPolicyInternal.x64=1\n"
                "SLPolicyOffset.x64=%IX\n"
                "SLPolicyFunc.x64=%s\n"
                : "SLPolicyInternal.x86=1\n"
                "SLPolicyOffset.x86=%IX\n"
                "SLPolicyFunc.x86=%s\n", addr, SLPolicyCP(&decoder, addr, base) ? "New_Win8SL_CP" : "New_Win8SL");
        }
        else puts("ERROR: SLGetWindowsInformationDWORDWrapper not found");
        ExitProcess(0);
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
        printf(decoder.stack_width == ZYDIS_STACK_WIDTH_64
            ? "SLInitHook.x64=1\n"
            "SLInitOffset.x64=%llX\n"
            "SLInitFunc.x64=New_CSLQuery_Initialize\n"
            : "SLInitHook.x86=1\n"
            "SLInitOffset.x86=%llX\n"
            "SLInitFunc.x86=New_CSLQuery_Initialize\n", symbol.Address - symbol.ModBase);

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
    ExitProcess(0);
}
