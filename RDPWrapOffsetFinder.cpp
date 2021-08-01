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

void LocalOnlyPatch(ZydisDecoder *pDecoder, DWORD64 IP, DWORD64 pdwBase, DWORD64 target) {
    ZyanUSize length = 256;
    ZydisDecodedInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void *)IP, length, &instruction)))
    {
        IP += instruction.length;
        length -= instruction.length;
        if (instruction.operand_count == 4 && instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            instruction.operands[0].imm.is_relative == ZYAN_TRUE &&
            instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            (instruction.operands[1].reg.value == ZYDIS_REGISTER_RIP ||
                instruction.operands[1].reg.value == ZYDIS_REGISTER_EIP) &&
            target == IP + instruction.operands[0].imm.value.u)
        {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)IP, length, &instruction)) ||
                instruction.mnemonic != ZYDIS_MNEMONIC_TEST) break;

            IP += instruction.length;
            length -= instruction.length;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)IP, length, &instruction)) ||
                instruction.operand_count != 3 ||
                instruction.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                instruction.operands[0].imm.is_relative != ZYAN_TRUE ||
                instruction.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                instruction.operands[1].reg.value != ZYDIS_REGISTER_RIP &&
                instruction.operands[1].reg.value != ZYDIS_REGISTER_EIP) break;

            if (instruction.mnemonic == ZYDIS_MNEMONIC_JNS)
            {
                target = IP + instruction.length;
                IP = target + instruction.operands[0].imm.value.u;
            }
            else if (instruction.mnemonic != ZYDIS_MNEMONIC_JS) break;
            else
            {
                IP += instruction.length;
                target = IP + instruction.operands[0].imm.value.u;
            }

            length -= instruction.length;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)IP, length, &instruction)) ||
                instruction.mnemonic != ZYDIS_MNEMONIC_CMP) break;

            IP += instruction.length;
            length -= instruction.length;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)IP, length, &instruction)) ||
                instruction.mnemonic != ZYDIS_MNEMONIC_JZ || instruction.operand_count != 3 ||
                instruction.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                instruction.operands[0].imm.is_relative != ZYAN_TRUE ||
                instruction.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                instruction.operands[1].reg.value != ZYDIS_REGISTER_RIP &&
                instruction.operands[1].reg.value != ZYDIS_REGISTER_EIP ||
                target != IP + instruction.operands[0].imm.value.u + instruction.length) break;

            const char* jmp = "jmpshort";
            if (instruction.raw.imm[0].offset == 2) jmp = "nopjmp";
            printf(pDecoder->address_width == ZYDIS_ADDRESS_WIDTH_64 
                ? "LocalOnlyPatch.x64=1\n"
                "LocalOnlyOffset.x64=%llX\n"
                "LocalOnlyCode.x64=%s\n"
                : "LocalOnlyPatch.x86=1\n"
                "LocalOnlyOffset.x86=%llX\n"
                "LocalOnlyCode.x86=%s\n", IP - pdwBase, jmp);
            return;
        }
    }
    puts("ERROR: LocalOnlyPatch patten not found");
}

void DefPolicyPatch(ZydisDecoder* pDecoder, DWORD64 IP, DWORD64 pdwBase) {
    ZyanUSize length = 128;
    ZyanUSize lastLength = 0;
    ZydisDecodedInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)IP, length, &instruction)))
    {
        if (instruction.operand_count == 3 && instruction.mnemonic == ZYDIS_MNEMONIC_CMP) 
        {
            const char* reg1;
            const char* reg2;
            if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                instruction.operands[0].mem.disp.value == 0x63c &&
                instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                reg1 = ZydisRegisterGetString(instruction.operands[1].reg.value);
                reg2 = ZydisRegisterGetString(instruction.operands[0].mem.base);
            }
            else if (instruction.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                instruction.operands[1].mem.disp.value == 0x320 &&
                instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                reg1 = ZydisRegisterGetString(instruction.operands[0].reg.value);
                reg2 = ZydisRegisterGetString(instruction.operands[1].mem.base);
            }
            else goto out;
            const char* jmp = "";

            length -= instruction.length;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)(IP + instruction.length), length, &instruction)))
                break;

            if (instruction.mnemonic == ZYDIS_MNEMONIC_JNZ)
            {
                IP -= lastLength;
                jmp = "_jmp";
            }
            else if (instruction.mnemonic != ZYDIS_MNEMONIC_JZ && instruction.mnemonic != ZYDIS_MNEMONIC_POP)
                break;

            printf(pDecoder->address_width == ZYDIS_ADDRESS_WIDTH_64 
                ? "DefPolicyPatch.x64=1\n"
                "DefPolicyOffset.x64=%llX\n"
                "DefPolicyCode.x64=CDefPolicy_Query_%s_%s%s\n"
                : "DefPolicyPatch.x86=1\n"
                "DefPolicyOffset.x86=%llX\n"
                "DefPolicyCode.x86=CDefPolicy_Query_%s_%s%s\n", IP - pdwBase, reg1, reg2, jmp);
            return;
        }
out:
        IP += instruction.length;
        length -= instruction.length;
        lastLength = instruction.length;
    }
    puts("ERROR: DefPolicyPatch patten not found");
}

int SingleUserPatch(ZydisDecoder* pDecoder, DWORD64 IP, DWORD64 pdwBase, DWORD64 target) {
    ZyanUSize length = 128;
    ZydisDecodedInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)IP, length, &instruction)))
    {
        IP += instruction.length;
        length -= instruction.length;
        if (instruction.operand_count == 4 && instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            instruction.operands[0].imm.is_relative == ZYAN_TRUE &&
            instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            (instruction.operands[1].reg.value == ZYDIS_REGISTER_RIP ||
                instruction.operands[1].reg.value == ZYDIS_REGISTER_EIP) &&
            target == IP + instruction.operands[0].imm.value.u)
        {
            while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)IP, length, &instruction)))
            {
                if (instruction.operand_count == 2 && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    instruction.operands[1].imm.value.u == 1)
                {
                    printf(pDecoder->address_width == ZYDIS_ADDRESS_WIDTH_64 
                        ? "SingleUserPatch.x64=1\n"
                        "SingleUserOffset.x64=%llX\n"
                        "SingleUserCode.x64=Zero\n"
                        : "SingleUserPatch.x86=1\n"
                        "SingleUserOffset.x86=%llX\n"
                        "SingleUserCode.x86=Zero\n", IP + instruction.raw.imm[0].offset - pdwBase);
                    return 1;
                } else if (instruction.operand_count == 2 && instruction.mnemonic == ZYDIS_MNEMONIC_INC &&
                    instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    printf(pDecoder->address_width == ZYDIS_ADDRESS_WIDTH_64
                        ? "SingleUserPatch.x64=1\n"
                        "SingleUserOffset.x64=%llX\n"
                        "SingleUserCode.x64=nop\n"
                        : "SingleUserPatch.x86=1\n"
                        "SingleUserOffset.x86=%llX\n"
                        "SingleUserCode.x86=nop\n", IP - pdwBase);
                    return 1;
                }
                IP += instruction.length;
                length -= instruction.length;
            }
            break;
        }
    }
    return 0;
}

int main(int argc, char** argv)
{
    HANDLE hProcess = GetCurrentProcess();
    char szTermsrv[MAX_PATH];
    SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS | SYMOPT_DEBUG | SYMOPT_UNDNAME);
    const char* symPath = NULL;
    GetEnvironmentVariableA("_NT_SYMBOL_PATH", NULL, 0);
    if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) symPath = "cache*;srv*https://msdl.microsoft.com/download/symbols";
    if (!SymInitialize(hProcess, symPath, FALSE)) return -1;
    if (argc >= 2) lstrcpyA(szTermsrv, argv[1]);
    else lstrcpyA(szTermsrv + GetSystemDirectoryA(szTermsrv, sizeof(szTermsrv) / sizeof(char)), "\\termsrv.dll");
    HMODULE hMod = LoadLibraryExA(szTermsrv, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hMod) return -2;
    DWORD64 base = (size_t)hMod & ~3;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(base);
    PIMAGE_NT_HEADERS64 pNT = (PIMAGE_NT_HEADERS64)(base + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);
    base -= pSection->VirtualAddress - pSection->PointerToRawData;

    const char* arch = "x64";
    ZydisDecoder decoder;
    if (pNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
        arch = "x86";
    }

    if (!SymLoadModuleEx(hProcess, NULL, szTermsrv, NULL, 0, 0, NULL, 0)) return -3;

    HRSRC hResInfo = FindResourceA(hMod, MAKEINTRESOURCEA(1), MAKEINTRESOURCEA(16));
    PVS_VERSIONINFO hResData = (PVS_VERSIONINFO)LoadResource(hMod, hResInfo);
    SYMBOL_INFO symbol;
    symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol.MaxNameLen = 0;

    printf("[%hu.%hu.%hu.%hu]\n", HIWORD(hResData->Value.dwFileVersionMS), LOWORD(hResData->Value.dwFileVersionMS),
        HIWORD(hResData->Value.dwFileVersionLS), LOWORD(hResData->Value.dwFileVersionLS));

    if (SymFromName(hProcess, "memset", &symbol) || SymFromName(hProcess, "_memset", &symbol))
    {
        DWORD64 target = symbol.Address - symbol.ModBase + base;
        if (SymFromName(hProcess, "CSessionArbitrationHelper::IsSingleSessionPerUserEnabled", &symbol) &&
            SingleUserPatch(&decoder, symbol.Address - symbol.ModBase + base, base, target));
        else if (SymFromName(hProcess, "CUtils::IsSingleSessionPerUser", &symbol))
            if(!SingleUserPatch(&decoder, symbol.Address - symbol.ModBase + base, base, target))
                puts("ERROR: SingleUserPatch not found");
    }

    if (SymFromName(hProcess, "CDefPolicy::Query", &symbol))
        DefPolicyPatch(&decoder, symbol.Address - symbol.ModBase + base, base);
    else puts("ERROR: CDefPolicy_Query not found");

    if (hResData->Value.dwFileVersionMS <= 0x00060001) return 0;

    if (hResData->Value.dwFileVersionMS == 0x00060002)
    {
        if (SymFromName(hProcess, "SLGetWindowsInformationDWORDWrapper", &symbol))
            _printf_p("SLPolicyInternal.%1$s=1\n"
                "SLPolicyOffset.%1$s=%2$llX\n"
                "SLPolicyFunc.%1$s=New_Win8SL\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: SLGetWindowsInformationDWORDWrapper not found");
        return 0;
    }

    if (SymFromName(hProcess, "CEnforcementCore::GetInstanceOfTSLicense", &symbol))
    {
        DWORD64 addr = symbol.Address - symbol.ModBase + base;
        if (SymFromName(hProcess, "CSLQuery::IsLicenseTypeLocalOnly", &symbol))
            LocalOnlyPatch(&decoder, addr, base, symbol.Address - symbol.ModBase + base);
        else puts("ERROR: IsLicenseTypeLocalOnly not found");
    } else puts("ERROR: GetInstanceOfTSLicense not found");

    if (SymFromName(hProcess, "CSLQuery::Initialize", &symbol))
    {
        _printf_p("SLInitHook.%1$s=1\n"
            "SLInitOffset.%1$s=%2$llX\n"
            "SLInitFunc.%1$s=New_CSLQuery_Initialize\n", arch, symbol.Address - symbol.ModBase);

        printf("\n[%hu.%hu.%hu.%hu-SLInit]\n", HIWORD(hResData->Value.dwFileVersionMS), LOWORD(hResData->Value.dwFileVersionMS),
            HIWORD(hResData->Value.dwFileVersionLS), LOWORD(hResData->Value.dwFileVersionLS));

        if (SymFromName(hProcess, "CSLQuery::bServerSku", &symbol))
            printf("bServerSku.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bServerSku not found");

        if (SymFromName(hProcess, "CSLQuery::bRemoteConnAllowed", &symbol))
            printf("bRemoteConnAllowed.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bRemoteConnAllowed not found");

        if (SymFromName(hProcess, "CSLQuery::bFUSEnabled", &symbol))
            printf("bFUSEnabled.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bFUSEnabled not found");

        if (SymFromName(hProcess, "CSLQuery::bAppServerAllowed", &symbol))
            printf("bAppServerAllowed.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bAppServerAllowed not found");

        if (SymFromName(hProcess, "CSLQuery::bMultimonAllowed", &symbol))
            printf("bMultimonAllowed.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bMultimonAllowed not found");

        if (SymFromName(hProcess, "CSLQuery::lMaxUserSessions", &symbol))
            printf("lMaxUserSessions.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: lMaxUserSessions not found");

        if (SymFromName(hProcess, "CSLQuery::ulMaxDebugSessions", &symbol))
            printf("ulMaxDebugSessions.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: ulMaxDebugSessions not found");

        if (SymFromName(hProcess, "CSLQuery::bInitialized", &symbol))
            printf("bInitialized.%s=%llX\n", arch, symbol.Address - symbol.ModBase);
        else puts("ERROR: bInitialized not found");
    } else puts("ERROR: CSLQuery_Initialize not found");
    return 0;
}
