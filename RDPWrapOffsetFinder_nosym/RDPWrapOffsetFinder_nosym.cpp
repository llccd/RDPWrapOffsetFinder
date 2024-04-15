#include <iostream>
#include <windows.h>
#include <Zydis/Zydis.h>

constexpr const char Query[] = "CDefPolicy::Query";
constexpr const char LocalOnly[] = "CSLQuery::IsTerminalTypeLocalOnly";
constexpr const char SingleSessionEnabled[] = "CSessionArbitrationHelper::IsSingleSessionPerUserEnabled";
constexpr const char InstanceOfLicense[] = "CEnforcementCore::GetInstanceOfTSLicense ";

constexpr const WCHAR AllowRemote[] = L"TerminalServices-RemoteConnectionManager-AllowRemoteConnections";
constexpr const WCHAR AllowMultipleSessions[] = L"TerminalServices-RemoteConnectionManager-AllowMultipleSessions";
constexpr const WCHAR AllowAppServer[] = L"TerminalServices-RemoteConnectionManager-AllowAppServerMode";
constexpr const WCHAR AllowMultimon[] = L"TerminalServices-RemoteConnectionManager-AllowMultimon";
constexpr const WCHAR MaxUserSessions[] = L"TerminalServices-RemoteConnectionManager-MaxUserSessions";
constexpr const WCHAR MaxDebugSessions[] = L"TerminalServices-RemoteConnectionManager-ce0ad219-4670-4988-98fb-89b14c2f072b-MaxSessions";

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

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    //    union {
    //        OPTIONAL ULONG ExceptionHandler;
    //        OPTIONAL ULONG FunctionEntry;
    //    };
    //    OPTIONAL ULONG ExceptionData[];
} UNWIND_INFO, * PUNWIND_INFO;

PIMAGE_SECTION_HEADER findSection(PIMAGE_NT_HEADERS64 pNT, const char* str)
{
    auto pSection = IMAGE_FIRST_SECTION(pNT);

    for (DWORD64 i = 0; i < pNT->FileHeader.NumberOfSections; i++)
        if (CSTR_EQUAL == CompareStringA(LOCALE_INVARIANT, 0, (char*)pSection[i].Name, -1, str, -1))
            return pSection + i;

    return NULL;
}

DWORD64 pattenMatch(DWORD64 base, PIMAGE_SECTION_HEADER pSection, const void *str, DWORD64 size)
{
    auto rdata = base + pSection->VirtualAddress;

    for (DWORD64 i = 0; i < pSection->SizeOfRawData; i += 4)
        if (!memcmp((void*)(rdata + i), str, size)) return pSection->VirtualAddress + i;

    return -1;
}

DWORD64 searchXref(ZydisDecoder* decoder, DWORD64 base, PRUNTIME_FUNCTION func, DWORD64 target)
{
    auto IP = base + func->BeginAddress;
    auto length = (ZyanUSize)func->EndAddress - func->BeginAddress;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
    {
        IP += instruction.length;
        length -= instruction.length;
        if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
            operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[1].mem.base == ZYDIS_REGISTER_RIP &&
            operands[1].mem.disp.value + IP == target + base &&
            operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            return IP - base;
    }

    return 0;
}

PRUNTIME_FUNCTION backtrace(DWORD64 base, PRUNTIME_FUNCTION func) {
    if (func->UnwindData & RUNTIME_FUNCTION_INDIRECT)
        func = (PRUNTIME_FUNCTION)(base + func->UnwindData & ~3);

    auto unwindInfo = (PUNWIND_INFO)(base + func->UnwindData);
    while (unwindInfo->Flags & UNW_FLAG_CHAININFO)
    {
        func = (PRUNTIME_FUNCTION) & (unwindInfo->UnwindCode[(unwindInfo->CountOfCodes + 1) & ~1]);
        unwindInfo = (PUNWIND_INFO)(base + func->UnwindData);
    }

    return func;
}

PIMAGE_IMPORT_DESCRIPTOR findImportImage(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, DWORD64 base, LPCSTR str) {
    while (pImportDescriptor->Name)
    {
        if(!lstrcmpiA((LPCSTR)(base + pImportDescriptor->Name), str)) return pImportDescriptor;
        pImportDescriptor++; 
    }
    return NULL;
}

DWORD64 findImportFunction(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, DWORD64 base, LPCSTR str) {
    auto pThunk = (PIMAGE_THUNK_DATA)(pImportDescriptor->OriginalFirstThunk + base);
    while (pThunk->u1.AddressOfData)
    {
        if (!lstrcmpiA(((PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + base))->Name, str))
            return (DWORD64)pThunk - base - pImportDescriptor->OriginalFirstThunk + pImportDescriptor->FirstThunk;
        pThunk++;
    }
    return -1;
}

void LocalOnlyPatch(ZydisDecoder *decoder, DWORD64 RVA, DWORD64 base, DWORD64 target) {
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
            operands[1].reg.value == ZYDIS_REGISTER_RIP &&
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
                operands[1].reg.value != ZYDIS_REGISTER_RIP) break;

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
                instruction.mnemonic != ZYDIS_MNEMONIC_JZ || instruction.operand_count != 3 ||
                operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                operands[0].imm.is_relative != ZYAN_TRUE ||
                operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                operands[1].reg.value != ZYDIS_REGISTER_RIP ||
                target != IP + operands[0].imm.value.u + instruction.length) break;

            const char* jmp = "jmpshort";
            if (instruction.raw.imm[0].offset == 2) jmp = "nopjmp";
            printf("LocalOnlyPatch.x64=1\n"
                "LocalOnlyOffset.x64=%llX\n"
                "LocalOnlyCode.x64=%s\n", IP - base, jmp);
            return;
        }
    }
    puts("ERROR: LocalOnlyPatch not found");
}

void DefPolicyPatch(ZydisDecoder* decoder, DWORD64 RVA, DWORD64 base) {
    ZyanUSize length = 128;
    ZyanUSize lastLength = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    auto IP = RVA + base;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
    {
        if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
            operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[0].mem.disp.value == 0x63c &&
            operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            const char* reg1 = ZydisRegisterGetString(operands[1].reg.value);
            const char* reg2 = ZydisRegisterGetString(operands[0].mem.base);
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

            printf("DefPolicyPatch.x64=1\n"
                "DefPolicyOffset.x64=%llX\n"
                "DefPolicyCode.x64=CDefPolicy_Query_%s_%s%s\n", IP - base, reg1, reg2, jmp);
            return;
        }

        IP += instruction.length;
        length -= instruction.length;
        lastLength = instruction.length;
    }
    puts("ERROR: DefPolicyPatch not found");
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
        if (instruction.operand_count == 4 && instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            operands[0].imm.is_relative == ZYAN_TRUE &&
            operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].reg.value == ZYDIS_REGISTER_RIP)
        {
            auto jmp_addr = IP + operands[0].imm.value.u;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)jmp_addr, length, &instruction, operands)) ||
                instruction.mnemonic != ZYDIS_MNEMONIC_JMP ||
                operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                operands[0].mem.base != ZYDIS_REGISTER_RIP ||
                operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                operands[1].reg.value != ZYDIS_REGISTER_RIP ||
                operands[0].mem.disp.value + jmp_addr + instruction.length != target) continue;

            while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
            {
                if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    operands[1].imm.value.u == 1)
                {
                    printf("SingleUserPatch.x64=1\n"
                        "SingleUserOffset.x64=%llX\n"
                        "SingleUserCode.x64=Zero\n", IP + instruction.raw.imm[0].offset - base);
                    return 1;
                } else if (instruction.mnemonic == ZYDIS_MNEMONIC_INC &&
                    operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    printf("SingleUserPatch.x64=1\n"
                        "SingleUserOffset.x64=%llX\n"
                        "SingleUserCode.x64=nop\n", IP - base);
                    return 1;
                } else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
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
    HMODULE hMod;
    if (argc >= 2) hMod = LoadLibraryExA(argv[1], NULL, DONT_RESOLVE_DLL_REFERENCES);
    else hMod = LoadLibraryExW(L"termsrv.dll", NULL, DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hMod) return -1;
    auto base = (size_t)hMod;
    auto pDos = (PIMAGE_DOS_HEADER)base;
    auto pNT = (PIMAGE_NT_HEADERS64)(base + pDos->e_lfanew);
    auto rdata = findSection(pNT, ".rdata");
    if (!rdata) rdata = findSection(pNT, ".text");
    
    auto CDefPolicy_Query = pattenMatch(base, rdata, Query, sizeof(Query) - 1);
    auto GetInstanceOfTSLicense = pattenMatch(base, rdata, InstanceOfLicense, sizeof(InstanceOfLicense) - 1);
    auto IsSingleSessionPerUserEnabled = pattenMatch(base, rdata, SingleSessionEnabled, sizeof(SingleSessionEnabled) - 1);
    auto IsSingleSessionPerUser = pattenMatch(base, rdata, "IsSingleSessionPerUser", sizeof("IsSingleSessionPerUser"));
    if (!memcmp((void*)(base + IsSingleSessionPerUser - 8), "CUtils::", 8)) IsSingleSessionPerUser -= 8;
    auto IsLicenseTypeLocalOnly = pattenMatch(base, rdata, LocalOnly, sizeof(LocalOnly) - 1);
    auto bRemoteConnAllowed = pattenMatch(base, rdata, AllowRemote, sizeof(AllowRemote));

    auto pImportDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
    auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + pImportDirectory->VirtualAddress);
    pImportDescriptor = findImportImage(pImportDescriptor, base, "msvcrt.dll");
    if (!pImportDescriptor) return -2;
    auto memset_addr = findImportFunction(pImportDescriptor, base, "memset");
    
    auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
    auto FunctionTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
    auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
    if (!FunctionTableSize) return -3;

    DWORD64 CDefPolicy_Query_addr = 0, GetInstanceOfTSLicense_addr = 0, IsSingleSessionPerUserEnabled_addr = 0,
        IsSingleSessionPerUser_addr = 0, IsLicenseTypeLocalOnly_addr = 0, bRemoteConnAllowed_xref;
    PRUNTIME_FUNCTION CSLQuery_Initialize_func = NULL;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    for (DWORD i = 0; i < FunctionTableSize; i++) {
        if (!CDefPolicy_Query_addr && searchXref(&decoder, base, FunctionTable + i, CDefPolicy_Query))
            CDefPolicy_Query_addr = backtrace(base, FunctionTable + i)->BeginAddress;
        else if (!GetInstanceOfTSLicense_addr && searchXref(&decoder, base, FunctionTable + i, GetInstanceOfTSLicense))
            GetInstanceOfTSLicense_addr = backtrace(base, FunctionTable + i)->BeginAddress;
        else if (!IsSingleSessionPerUserEnabled_addr && searchXref(&decoder, base, FunctionTable + i, IsSingleSessionPerUserEnabled))
            IsSingleSessionPerUserEnabled_addr = backtrace(base, FunctionTable + i)->BeginAddress;
        else if (!IsSingleSessionPerUser_addr && searchXref(&decoder, base, FunctionTable + i, IsSingleSessionPerUser))
            IsSingleSessionPerUser_addr = backtrace(base, FunctionTable + i)->BeginAddress;
        else if (!IsLicenseTypeLocalOnly_addr && searchXref(&decoder, base, FunctionTable + i, IsLicenseTypeLocalOnly))
            IsLicenseTypeLocalOnly_addr = backtrace(base, FunctionTable + i)->BeginAddress;
        else if (!CSLQuery_Initialize_func && (bRemoteConnAllowed_xref = searchXref(&decoder, base, FunctionTable + i, bRemoteConnAllowed)))
            CSLQuery_Initialize_func = backtrace(base, FunctionTable + i);
        if (CDefPolicy_Query_addr && GetInstanceOfTSLicense_addr && IsSingleSessionPerUserEnabled_addr &&
            IsSingleSessionPerUser_addr && IsLicenseTypeLocalOnly_addr && CSLQuery_Initialize_func) break;
    }

    auto hResInfo = FindResourceW(hMod, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(16));
    if (!hResInfo) return -4;
    auto hResData = (PVS_VERSIONINFO)LoadResource(hMod, hResInfo);
    if (!hResData) return -5;

    printf("[%hu.%hu.%hu.%hu]\n", HIWORD(hResData->Value.dwFileVersionMS), LOWORD(hResData->Value.dwFileVersionMS),
        HIWORD(hResData->Value.dwFileVersionLS), LOWORD(hResData->Value.dwFileVersionLS));

    if (memset_addr)
    {
        if (IsSingleSessionPerUserEnabled_addr &&
            SingleUserPatch(&decoder, IsSingleSessionPerUserEnabled_addr, base, memset_addr));
        else if (IsSingleSessionPerUser_addr)
            if(!SingleUserPatch(&decoder, IsSingleSessionPerUser_addr, base, memset_addr))
                puts("ERROR: SingleUserPatch not found");
    }

    if (CDefPolicy_Query_addr)
        DefPolicyPatch(&decoder, CDefPolicy_Query_addr, base);
    else puts("ERROR: CDefPolicy_Query not found");

    if (hResData->Value.dwFileVersionMS <= 0x00060001) return 0;

    if (!CSLQuery_Initialize_func) {
        puts("ERROR: CSLQuery_Initialize not found");
        return 0;
    }

    auto IP = CSLQuery_Initialize_func->BeginAddress + base;
    auto length = (ZyanUSize)CSLQuery_Initialize_func->EndAddress - CSLQuery_Initialize_func->BeginAddress;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (hResData->Value.dwFileVersionMS == 0x00060002)
    {
        IP = bRemoteConnAllowed_xref + base;

        while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)IP, length, &instruction, operands))) {
            IP += instruction.length;
            length -= instruction.length;
            if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
                operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[0].imm.is_relative == ZYAN_TRUE &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].reg.value == ZYDIS_REGISTER_RIP)
            {
                printf("SLPolicyInternal.x64=1\n"
                    "SLPolicyOffset.x64=%llX\n"
                    "SLPolicyFunc.x64=New_Win8SL\n", IP + operands[0].imm.value.u - base);
                return 0;
            } 
        }

        puts("ERROR: SLGetWindowsInformationDWORDWrapper not found");
        return 0;
    }

    if (GetInstanceOfTSLicense_addr)
    {
        if (IsLicenseTypeLocalOnly_addr)
            LocalOnlyPatch(&decoder, GetInstanceOfTSLicense_addr, base, IsLicenseTypeLocalOnly_addr);
        else puts("ERROR: IsLicenseTypeLocalOnly not found");
    } else puts("ERROR: GetInstanceOfTSLicense not found");

    printf("SLInitHook.x64=1\n"
        "SLInitOffset.x64=%lX\n"
        "SLInitFunc.x64=New_CSLQuery_Initialize\n", CSLQuery_Initialize_func->BeginAddress);

    printf("\n[%hu.%hu.%hu.%hu-SLInit]\n", HIWORD(hResData->Value.dwFileVersionMS), LOWORD(hResData->Value.dwFileVersionMS),
        HIWORD(hResData->Value.dwFileVersionLS), LOWORD(hResData->Value.dwFileVersionLS));

    auto bFUSEnabled = pattenMatch(base, rdata, AllowMultipleSessions, sizeof(AllowMultipleSessions));
    auto bAppServerAllowed = pattenMatch(base, rdata, AllowAppServer, sizeof(AllowAppServer));
    auto bMultimonAllowed = pattenMatch(base, rdata, AllowMultimon, sizeof(AllowMultimon));
    auto lMaxUserSessions = pattenMatch(base, rdata, MaxUserSessions, sizeof(MaxUserSessions));
    auto ulMaxDebugSessions = pattenMatch(base, rdata, MaxDebugSessions, sizeof(MaxDebugSessions));
        
    DWORD64 bServerSku_addr = 0, bRemoteConnAllowed_addr = 0, bFUSEnabled_addr = 0, bAppServerAllowed_addr = 0,
        bMultimonAllowed_addr = 0, lMaxUserSessions_addr = 0, ulMaxDebugSessions_addr = 0, bInitialized_addr = 0;
    auto current = &bServerSku_addr;

    if (length > 100)
        while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)IP, length, &instruction, operands)))
        {
            IP += instruction.length;
            length -= instruction.length;
            if (!*current && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[0].mem.base == ZYDIS_REGISTER_RIP &&
                operands[0].mem.disp.has_displacement == ZYAN_TRUE &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].reg.value == ZYDIS_REGISTER_EAX)
                *current = operands[0].mem.disp.value + IP - base;
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
                operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[1].mem.base == ZYDIS_REGISTER_RIP &&
                operands[1].mem.disp.has_displacement == ZYAN_TRUE &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[0].reg.value == ZYDIS_REGISTER_RCX)
            {
                DWORD64 target = operands[1].mem.disp.value + IP - base;
                if (target == bRemoteConnAllowed) current = &bRemoteConnAllowed_addr;
                else if (target == bFUSEnabled) current = &bFUSEnabled_addr;
                else if (target == bAppServerAllowed) current = &bAppServerAllowed_addr;
                else if (target == bMultimonAllowed) current = &bMultimonAllowed_addr;
                else if (target == lMaxUserSessions) current = &lMaxUserSessions_addr;
                else if (target == ulMaxDebugSessions) current = &ulMaxDebugSessions_addr;
            }
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[0].mem.base == ZYDIS_REGISTER_RIP &&
                operands[0].mem.disp.has_displacement == ZYAN_TRUE &&
                operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[1].imm.value.u == 1) {
                bInitialized_addr = operands[0].mem.disp.value + IP - base;
                break;
            }
        }
    else {
        length = 0x11000;
        while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)IP, length, &instruction, operands)))
        {
            IP += instruction.length;
            length -= instruction.length;
            if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP &&
                operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[0].imm.is_relative == ZYAN_TRUE &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].reg.value == ZYDIS_REGISTER_RIP)
                IP += operands[0].imm.value.u;
            else if (!*current && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[0].mem.base == ZYDIS_REGISTER_RIP &&
                operands[0].mem.disp.has_displacement == ZYAN_TRUE &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                *current = operands[0].mem.disp.value + IP - base;
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
                operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[1].mem.base == ZYDIS_REGISTER_RIP &&
                operands[1].mem.disp.has_displacement == ZYAN_TRUE &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[0].reg.value == ZYDIS_REGISTER_RDX)
            {
                DWORD64 target = operands[1].mem.disp.value + IP - base;
                if (target == bRemoteConnAllowed) current = &bRemoteConnAllowed_addr;
                else if (target == bFUSEnabled) current = &bFUSEnabled_addr;
                else if (target == bAppServerAllowed) current = &bAppServerAllowed_addr;
                else if (target == bMultimonAllowed) current = &bMultimonAllowed_addr;
                else if (target == lMaxUserSessions) current = &lMaxUserSessions_addr;
                else if (target == ulMaxDebugSessions) current = &ulMaxDebugSessions_addr;
            }
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[0].mem.base == ZYDIS_REGISTER_RIP &&
                operands[0].mem.disp.has_displacement == ZYAN_TRUE &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].reg.value == ZYDIS_REGISTER_EAX)
                bInitialized_addr = operands[0].mem.disp.value + IP - base;
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_RET)
                break;
        }
    }

    if (bServerSku_addr)
        printf("bServerSku.x64=%llX\n", bServerSku_addr);
    else puts("ERROR: bServerSku not found");

    if (bRemoteConnAllowed_addr)
        printf("bRemoteConnAllowed.x64=%llX\n", bRemoteConnAllowed_addr);
    else puts("ERROR: bRemoteConnAllowed not found");

    if (bFUSEnabled_addr)
        printf("bFUSEnabled.x64=%llX\n", bFUSEnabled_addr);
    else puts("ERROR: bFUSEnabled not found");

    if (bAppServerAllowed_addr)
        printf("bAppServerAllowed.x64=%llX\n", bAppServerAllowed_addr);
    else puts("ERROR: bAppServerAllowed not found");

    if (bMultimonAllowed_addr)
        printf("bMultimonAllowed.x64=%llX\n", bMultimonAllowed_addr);
    else puts("ERROR: bMultimonAllowed not found");

    if (lMaxUserSessions_addr)
        printf("lMaxUserSessions.x64=%llX\n", lMaxUserSessions_addr);
    else puts("ERROR: lMaxUserSessions not found");

    if (ulMaxDebugSessions_addr)
        printf("ulMaxDebugSessions.x64=%llX\n", ulMaxDebugSessions_addr);
    else puts("ERROR: ulMaxDebugSessions not found");

    if (bInitialized_addr)
        printf("bInitialized.x64=%llX\n", bInitialized_addr);
    else puts("ERROR: bInitialized not found");

    return 0;
}
