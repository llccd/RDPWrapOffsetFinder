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

void LocalOnlyPatch(ZydisDecoder * decoder, DWORD64 RVA, DWORD64 base, DWORD64 target) {
    ZyanUSize length = 256;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    auto IP = RVA + base;
    target += base;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void *)IP, length, &instruction, operands)))
    {
        IP += instruction.length;
        length -= instruction.length;
        if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            operands[0].imm.is_relative == ZYAN_TRUE &&
            operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            (operands[1].reg.value == ZYDIS_REGISTER_RIP ||
                operands[1].reg.value == ZYDIS_REGISTER_EIP) &&
            target == IP + operands[0].imm.value.u)
        {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)IP, length, &instruction)) ||
                instruction.mnemonic != ZYDIS_MNEMONIC_TEST) break;

            IP += instruction.length;
            length -= instruction.length;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)) ||
                instruction.operand_count != 3 ||
                operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                operands[0].imm.is_relative != ZYAN_TRUE ||
                operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                operands[1].reg.value != ZYDIS_REGISTER_RIP &&
                operands[1].reg.value != ZYDIS_REGISTER_EIP) break;

            if (instruction.mnemonic == ZYDIS_MNEMONIC_JNS)
            {
                target = IP + instruction.length;
                IP = target + operands[0].imm.value.u;
            }
            else if (instruction.mnemonic != ZYDIS_MNEMONIC_JS) break;
            else
            {
                IP += instruction.length;
                target = IP + operands[0].imm.value.u;
            }

            length -= instruction.length;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)IP, length, &instruction)) ||
                instruction.mnemonic != ZYDIS_MNEMONIC_CMP) break;

            IP += instruction.length;
            length -= instruction.length;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)) ||
                instruction.mnemonic != ZYDIS_MNEMONIC_JZ ||
                operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                operands[0].imm.is_relative != ZYAN_TRUE ||
                operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                operands[1].reg.value != ZYDIS_REGISTER_RIP &&
                operands[1].reg.value != ZYDIS_REGISTER_EIP ||
                target != IP + operands[0].imm.value.u + instruction.length) break;

            const char* jmp = "jmpshort";
            if (instruction.raw.imm[0].offset == 2) jmp = "nopjmp";
            printf(decoder->stack_width == ZYDIS_STACK_WIDTH_64
                ? "LocalOnlyPatch.x64=1\n"
                "LocalOnlyOffset.x64=%llX\n"
                "LocalOnlyCode.x64=%s\n"
                : "LocalOnlyPatch.x86=1\n"
                "LocalOnlyOffset.x86=%llX\n"
                "LocalOnlyCode.x86=%s\n", IP - base, jmp);
            return;
        }
    }
    puts("ERROR: LocalOnlyPatch patten not found");
}

void DefPolicyPatch(ZydisDecoder* decoder, DWORD64 RVA, DWORD64 base) {
    ZyanUSize length = 128;
    ZyanUSize lastLength = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    auto IP = RVA + base;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
    {
        if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP) 
        {
            const char* reg1;
            const char* reg2;
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[0].mem.disp.value == 0x63c &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                reg1 = ZydisRegisterGetString(operands[1].reg.value);
                reg2 = ZydisRegisterGetString(operands[0].mem.base);
            }
            else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[1].mem.disp.value == 0x320 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                reg1 = ZydisRegisterGetString(operands[0].reg.value);
                reg2 = ZydisRegisterGetString(operands[1].mem.base);
            }
            else goto out;
            const char* jmp = "";

            length -= instruction.length;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)(IP + instruction.length), length, &instruction)))
                break;

            if (instruction.mnemonic == ZYDIS_MNEMONIC_JNZ)
            {
                IP -= lastLength;
                jmp = "_jmp";
            }
            else if (instruction.mnemonic != ZYDIS_MNEMONIC_JZ && instruction.mnemonic != ZYDIS_MNEMONIC_POP)
                break;

            printf(decoder->stack_width == ZYDIS_STACK_WIDTH_64
                ? "DefPolicyPatch.x64=1\n"
                "DefPolicyOffset.x64=%llX\n"
                "DefPolicyCode.x64=CDefPolicy_Query_%s_%s%s\n"
                : "DefPolicyPatch.x86=1\n"
                "DefPolicyOffset.x86=%llX\n"
                "DefPolicyCode.x86=CDefPolicy_Query_%s_%s%s\n", IP - base, reg1, reg2, jmp);
            return;
        }
out:
        IP += instruction.length;
        length -= instruction.length;
        lastLength = instruction.length;
    }
    puts("ERROR: DefPolicyPatch patten not found");
}

int SingleUserPatch(ZydisDecoder* decoder, DWORD64 RVA, DWORD64 base, DWORD64 target) {
    ZyanUSize length = 128;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    auto IP = RVA + base;
    target += base;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
    {
        IP += instruction.length;
        length -= instruction.length;
        if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            operands[0].imm.is_relative == ZYAN_TRUE &&
            operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            (operands[1].reg.value == ZYDIS_REGISTER_RIP ||
                operands[1].reg.value == ZYDIS_REGISTER_EIP) &&
            target == IP + operands[0].imm.value.u)
        {
            while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
            {
                if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    operands[1].imm.value.u == 1)
                {
                    printf(decoder->stack_width == ZYDIS_STACK_WIDTH_64
                        ? "SingleUserPatch.x64=1\n"
                        "SingleUserOffset.x64=%llX\n"
                        "SingleUserCode.x64=Zero\n"
                        : "SingleUserPatch.x86=1\n"
                        "SingleUserOffset.x86=%llX\n"
                        "SingleUserCode.x86=Zero\n", IP + instruction.raw.imm[0].offset - base);
                    return 1;
                } else if (instruction.mnemonic == ZYDIS_MNEMONIC_INC &&
                    operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    printf(decoder->stack_width == ZYDIS_STACK_WIDTH_64
                        ? "SingleUserPatch.x64=1\n"
                        "SingleUserOffset.x64=%llX\n"
                        "SingleUserCode.x64=nop\n"
                        : "SingleUserPatch.x86=1\n"
                        "SingleUserOffset.x86=%llX\n"
                        "SingleUserCode.x86=nop\n", IP - base);
                    return 1;
                } else if (decoder->stack_width == ZYDIS_STACK_WIDTH_64 &&
                    instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
                    operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[0].reg.value >= ZYDIS_REGISTER_EAX && operands[0].reg.value < ZYDIS_REGISTER_RAX &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    operands[1].mem.base >= ZYDIS_REGISTER_RAX && operands[1].mem.base <= ZYDIS_REGISTER_R15 &&
                    operands[1].mem.disp.value == 1) {
                    printf("SingleUserPatch.x64=1\n"
                        "SingleUserOffset.x64=%llX\n"
                        "SingleUserCode.x64=Zero\n", IP + instruction.raw.disp.offset - base);
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
    auto hProcess = GetCurrentProcess();
    char szTermsrv[MAX_PATH];
    SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS | SYMOPT_DEBUG | SYMOPT_UNDNAME);
    LPCWSTR symPath = NULL;
    GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", NULL, 0);
    if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) symPath = L"cache*;srv*https://msdl.microsoft.com/download/symbols";
    if (!SymInitializeW(hProcess, symPath, FALSE)) return -1;
    if (argc >= 2) lstrcpyA(szTermsrv, argv[1]);
    else lstrcpyA(szTermsrv + GetSystemDirectoryA(szTermsrv, sizeof(szTermsrv) / sizeof(char)), "\\termsrv.dll");
    auto hMod = LoadLibraryExA(szTermsrv, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hMod) return -2;
    auto base = (size_t)hMod & ~3;
    auto pDos = (PIMAGE_DOS_HEADER)(base);
    auto pNT = (PIMAGE_NT_HEADERS64)(base + pDos->e_lfanew);
    auto pSection = IMAGE_FIRST_SECTION(pNT);
    base += (DWORD64)pSection->PointerToRawData - pSection->VirtualAddress;

    const char* arch = "x64";
    ZydisDecoder decoder;
    if (pNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
        arch = "x86";
    }

    if (!SymLoadModuleEx(hProcess, NULL, szTermsrv, NULL, 0, 0, NULL, 0)) return -3;

    auto hResInfo = FindResourceW(hMod, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(16));
    if (!hResInfo) return -4;
    auto hResData = (PVS_VERSIONINFO)LoadResource(hMod, hResInfo);
    if (!hResData) return -5;

    SYMBOL_INFOW symbol;
    symbol.SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol.MaxNameLen = 0;

    printf("[%hu.%hu.%hu.%hu]\n", HIWORD(hResData->Value.dwFileVersionMS), LOWORD(hResData->Value.dwFileVersionMS),
        HIWORD(hResData->Value.dwFileVersionLS), LOWORD(hResData->Value.dwFileVersionLS));

    if (SymFromNameW(hProcess, L"memset", &symbol) || SymFromNameW(hProcess, L"_memset", &symbol))
    {
        auto target = symbol.Address - symbol.ModBase;
        if (SymFromNameW(hProcess, L"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled", &symbol) &&
            SingleUserPatch(&decoder, symbol.Address - symbol.ModBase, base, target));
        else if (SymFromNameW(hProcess, L"CUtils::IsSingleSessionPerUser", &symbol))
            if(!SingleUserPatch(&decoder, symbol.Address - symbol.ModBase, base, target))
                puts("ERROR: SingleUserPatch not found");
    }

    if (SymFromNameW(hProcess, L"CDefPolicy::Query", &symbol))
        DefPolicyPatch(&decoder, symbol.Address - symbol.ModBase, base);
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
        auto addr = symbol.Address - symbol.ModBase;
        if (SymFromNameW(hProcess, L"CSLQuery::IsLicenseTypeLocalOnly", &symbol))
            LocalOnlyPatch(&decoder, addr, base, symbol.Address - symbol.ModBase);
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
