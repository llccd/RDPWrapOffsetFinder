#include <iostream>
#include <windows.h>
#include <Dbghelp.h>
#include <Zydis/Zydis.h>

#if _WIN64
#define HEX "%llX"
#define ARCH "x64"
#define ADDR DWORD64
#define REG_IP ZYDIS_REGISTER_RIP
#define SLGetWindowsInformationDWORDWrapper "?SLGetWindowsInformationDWORDWrapper@@YAJPEBGPEAK@Z"
#define CUtils_IsSingleSessionPerUser "?IsSingleSessionPerUser@CUtils@@SAJPEAH@Z"
#define CSessionArbitrationHelper_IsSingleSessionPerUser "?IsSingleSessionPerUserEnabled@CSessionArbitrationHelper@@UEAAJPEAH@Z"
#define CDefPolicy_Query "?Query@CDefPolicy@@UEAAJPEAH@Z"
#define CSLQuery_Initialize "?Initialize@CSLQuery@@SAJXZ"
#define CSLQuery_IsLicenseTypeLocalOnly "?IsLicenseTypeLocalOnly@CSLQuery@@SAJAEAU_GUID@@PEAH@Z"
#define CEnforcementCore_GetInstanceOfTSLicense "?GetInstanceOfTSLicense@CEnforcementCore@@UEAAJAEAU_GUID@@PEAPEAVITSLicense@@@Z"
#else
#define HEX "%lX"
#define ARCH "x86"
#define ADDR DWORD32
#define REG_IP ZYDIS_REGISTER_EIP
#define SLGetWindowsInformationDWORDWrapper "?SLGetWindowsInformationDWORDWrapper@@YGJPBGPAK@Z"
#define CUtils_IsSingleSessionPerUser "?IsSingleSessionPerUser@CUtils@@SGJPAH@Z"
#define CSessionArbitrationHelper_IsSingleSessionPerUser "?IsSingleSessionPerUserEnabled@CSessionArbitrationHelper@@UAGJPAH@Z"
#define CDefPolicy_Query "?Query@CDefPolicy@@UAEJPAH@Z"
#define CSLQuery_Initialize "?Initialize@CSLQuery@@SGJXZ"
#define CSLQuery_IsLicenseTypeLocalOnly "?IsLicenseTypeLocalOnly@CSLQuery@@SGJAAU_GUID@@PAH@Z"
#define CEnforcementCore_GetInstanceOfTSLicense "?GetInstanceOfTSLicense@CEnforcementCore@@UAGJAAU_GUID@@PAPAVITSLicense@@@Z"
#endif

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

void LocalOnlyPatch(ZydisDecoder *pDecoder, ADDR IP, ADDR pdwBase, ADDR target) {
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
            instruction.operands[1].reg.value == REG_IP &&
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
                instruction.operands[1].reg.value != REG_IP) break;

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
                instruction.operands[1].reg.value != REG_IP ||
                target != IP + instruction.operands[0].imm.value.u + instruction.length) break;

            const char* jmp = "jmpshort";
            if (instruction.raw.imm[0].offset == 2) jmp = "nopjmp";
            printf("LocalOnlyPatch." ARCH "=1\n"
                "LocalOnlyOffset." ARCH "=" HEX "\n"
                "LocalOnlyCode." ARCH "=%s\n", IP - pdwBase, jmp);
            return;
        }
    }
    puts("ERROR: LocalOnlyPatch patten not found");
}

void DefPolicyPatch(ZydisDecoder* pDecoder, ADDR IP, ADDR pdwBase) {
    ZyanUSize length = 128;
    ZyanUSize lastLength = 0;
    ZydisDecodedInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)IP, length, &instruction)))
    {
        if (instruction.operand_count == 3 && instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
#if _WIN64
            instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            instruction.operands[0].mem.disp.value == 0x63c &&
            instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            const char* reg1 = ZydisRegisterGetString(instruction.operands[1].reg.value);
            const char* reg2 = ZydisRegisterGetString(instruction.operands[0].mem.base);
#else
            instruction.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            instruction.operands[1].mem.disp.value == 0x320 &&
            instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            const char* reg1 = ZydisRegisterGetString(instruction.operands[0].reg.value);
            const char* reg2 = ZydisRegisterGetString(instruction.operands[1].mem.base);
#endif
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

            printf("DefPolicyPatch." ARCH "=1\n"
                "DefPolicyOffset." ARCH "=" HEX "\n"
                "DefPolicyCode." ARCH "=CDefPolicy_Query_%s_%s%s\n", IP - pdwBase, reg1, reg2, jmp);
            return;
        }

        IP += instruction.length;
        length -= instruction.length;
        lastLength = instruction.length;
    }
    puts("ERROR: DefPolicyPatch patten not found");
}

int SingleUserPatch(ZydisDecoder* pDecoder, ADDR IP, ADDR pdwBase, ADDR target) {
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
            instruction.operands[1].reg.value == REG_IP &&
            target == IP + instruction.operands[0].imm.value.u)
        {
            while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (void*)IP, length, &instruction)))
            {
                if (instruction.operand_count == 2 && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    instruction.operands[1].imm.value.u == 1)
                {
                    printf("SingleUserPatch." ARCH "=1\n"
                        "SingleUserOffset." ARCH "=" HEX "\n"
                        "SingleUserCode." ARCH "=Zero\n", IP + instruction.raw.imm[0].offset - pdwBase);
                    return 1;
                } else if (instruction.operand_count == 2 && instruction.mnemonic == ZYDIS_MNEMONIC_INC &&
                    instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    printf("SingleUserPatch." ARCH "=1\n"
                        "SingleUserOffset." ARCH "=" HEX "\n"
                        "SingleUserCode." ARCH "=nop\n", IP - pdwBase);
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
    SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS | SYMOPT_DEBUG);
    const char* symPath = NULL;
    GetEnvironmentVariableA("_NT_SYMBOL_PATH", NULL, 0);
    if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) symPath = "cache*;srv*https://msdl.microsoft.com/download/symbols";
    if (!SymInitialize(hProcess, symPath, FALSE)) ExitProcess(-1);
    if (argc >= 2) lstrcpyA(szTermsrv, argv[1]);
    else lstrcpyA(szTermsrv + GetSystemDirectoryA(szTermsrv, sizeof(szTermsrv) / sizeof(char)), "\\termsrv.dll");
    HMODULE hMod = LoadLibraryExA(szTermsrv, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) ExitProcess(-2);
    if (!SymLoadModule(hProcess, NULL, szTermsrv, NULL, (ADDR)hMod, 0)) ExitProcess(-3);
    HRSRC hResInfo = FindResourceA(hMod, MAKEINTRESOURCEA(1), MAKEINTRESOURCEA(16));
    PVS_VERSIONINFO hResData = (PVS_VERSIONINFO)LoadResource(hMod, hResInfo);
    uint16_t *pointer = (uint16_t*)&hResData->Value.dwFileVersionMS;
    SYMBOL_INFO symbol;
    symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol.MaxNameLen = 0;

    printf("[%hu.%hu.%hu.%hu]\n", *(pointer + 1), *pointer, *(pointer + 3), *(pointer + 2));
    ZydisDecoder decoder;
#if _WIN64
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#endif

    if (SymFromName(hProcess, "memset", &symbol) || SymFromName(hProcess, "_memset", &symbol))
    {
        ADDR target = symbol.Address;
        if (SymFromName(hProcess, CSessionArbitrationHelper_IsSingleSessionPerUser, &symbol) &&
            SingleUserPatch(&decoder, symbol.Address, symbol.ModBase, target));
        else if (SymFromName(hProcess, CUtils_IsSingleSessionPerUser, &symbol))
            if(!SingleUserPatch(&decoder, symbol.Address, symbol.ModBase, target))
                puts("ERROR: SingleUserPatch patten not found");
    }

    if (SymFromName(hProcess, CDefPolicy_Query, &symbol))
        DefPolicyPatch(&decoder, symbol.Address, symbol.ModBase);

    if (hResData->Value.dwFileVersionMS <= 0x00060001) return 0;

    if (hResData->Value.dwFileVersionMS == 0x00060002)
    {
        if (SymFromName(hProcess, SLGetWindowsInformationDWORDWrapper, &symbol))
            printf("SLPolicyInternal." ARCH "=1\n"
                "SLPolicyOffset." ARCH "=%llX\n"
                "SLPolicyFunc." ARCH "=New_Win8SL\n", symbol.Address - symbol.ModBase);
        else puts("ERROR: SLGetWindowsInformationDWORDWrapper not found");
        return 0;
    }

    if (SymFromName(hProcess, CEnforcementCore_GetInstanceOfTSLicense, &symbol))
    {
        ADDR addr = symbol.Address;
        if (SymFromName(hProcess, CSLQuery_IsLicenseTypeLocalOnly, &symbol))
            LocalOnlyPatch(&decoder, addr, symbol.ModBase, symbol.Address);
        else puts("ERROR: CSLQuery_IsLicenseTypeLocalOnly not found");
    } else puts("ERROR: CEnforcementCore_GetInstanceOfTSLicense not found");

    if (SymFromName(hProcess, CSLQuery_Initialize, &symbol))
    {
        printf("SLInitHook." ARCH "=1\n"
            "SLInitOffset." ARCH "=%llX\n"
            "SLInitFunc." ARCH "=New_CSLQuery_Initialize\n", symbol.Address - symbol.ModBase);

        printf("\n[%hu.%hu.%hu.%hu-SLInit]\n", *(pointer + 1), *pointer, *(pointer + 3), *(pointer + 2));

        if (SymFromName(hProcess, "?bServerSku@CSLQuery@@0HA", &symbol))
            printf("bServerSku." ARCH "=%llX\n", symbol.Address - symbol.ModBase);
        else puts("ERROR: bServerSku not found");

        if (SymFromName(hProcess, "?bRemoteConnAllowed@CSLQuery@@0HA", &symbol))
            printf("bRemoteConnAllowed." ARCH "=%llX\n", symbol.Address - symbol.ModBase);
        else puts("ERROR: bRemoteConnAllowed not found");

        if (SymFromName(hProcess, "?bFUSEnabled@CSLQuery@@0HA", &symbol))
            printf("bFUSEnabled." ARCH "=%llX\n", symbol.Address - symbol.ModBase);
        else puts("ERROR: bFUSEnabled not found");

        if (SymFromName(hProcess, "?bAppServerAllowed@CSLQuery@@0HA", &symbol))
            printf("bAppServerAllowed." ARCH "=%llX\n", symbol.Address - symbol.ModBase);
        else puts("ERROR: bAppServerAllowed not found");

        if (SymFromName(hProcess, "?bMultimonAllowed@CSLQuery@@0HA", &symbol))
            printf("bMultimonAllowed." ARCH "=%llX\n", symbol.Address - symbol.ModBase);
        else puts("ERROR: bMultimonAllowed not found");

        if (SymFromName(hProcess, "?lMaxUserSessions@CSLQuery@@0JA", &symbol))
            printf("lMaxUserSessions." ARCH "=%llX\n", symbol.Address - symbol.ModBase);
        else puts("ERROR: lMaxUserSessions not found");

        if (SymFromName(hProcess, "?ulMaxDebugSessions@CSLQuery@@0KA", &symbol))
            printf("ulMaxDebugSessions." ARCH "=%llX\n", symbol.Address - symbol.ModBase);
        else puts("ERROR: ulMaxDebugSessions not found");

        if (SymFromName(hProcess, "?bInitialized@CSLQuery@@0HA", &symbol))
            printf("bInitialized." ARCH "=%llX\n", symbol.Address - symbol.ModBase);
        else puts("ERROR: bInitialized not found");
    } else puts("ERROR: CSLQuery_Initialize not found");
    return 0;
}
