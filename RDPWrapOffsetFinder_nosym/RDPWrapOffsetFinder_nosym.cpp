#include <iostream>
#include <queue>
#include <forward_list>
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

#ifndef _WIN64
#define RUNTIME_FUNCTION_INDIRECT 0x1
#define UNW_FLAG_CHAININFO      0x4
#endif // _WIN64

class range {
private:
    std::forward_list<std::pair<size_t, size_t>> list;
public:
    bool in_range(size_t val) {
        for (auto& p : list) {
            if (val < p.first) return false;
            if (val < p.second) return true;
        }
        return false;
    }
    size_t next_val(size_t val) {
        for (auto& p : list) {
            if (val < p.first) break;
            if (val < p.second) {
                val = p.second;
                break;
            }
        }
        return val;
    }
    void clear() {
        list.clear();
    }
    bool empty() {
        return list.empty();
    }
    void add(size_t start, size_t end) {
        auto p = std::make_pair(start, end);
        auto it = list.begin();
        auto prev = &*it;
        if (list.empty() || end < prev->first) {
            list.emplace_front(p);
            return;
        }
        if (end <= prev->second) {
            if (start < prev->first) prev->first = start;
            return;
        }
        while (next(it) != list.end()) {
            auto& i = *next(it);
            if (end < i.first) {
                if (start > prev->second) list.emplace_after(it, p);
                else prev->second = end;
                return;
            }
            if (end <= i.second) {
                if (start < i.first)
                    if (start > prev->second) i.first = start;
                    else {
                        prev->second = i.second;
                        list.erase_after(it);
                    }
                return;
            }
            prev = &i;
            it++;
        }
        if (start > prev->second) list.emplace_after(it, p);
        else if (start >= prev->first && end > prev->second) prev->second = end;
    }
};

PIMAGE_SECTION_HEADER findSection(PIMAGE_NT_HEADERS64 pNT, const char* str)
{
    auto pSection = IMAGE_FIRST_SECTION(pNT);

    for (size_t i = 0; i < pNT->FileHeader.NumberOfSections; i++)
        if (CSTR_EQUAL == CompareStringA(LOCALE_INVARIANT, 0, (char*)pSection[i].Name, -1, str, -1))
            return pSection + i;

    return NULL;
}

size_t pattenMatch(size_t base, PIMAGE_SECTION_HEADER pSection, const void *str, size_t size)
{
    size_t rdata = base + pSection->VirtualAddress;

    for (size_t i = 0; i < pSection->SizeOfRawData; i += 4)
        if (!memcmp((void*)(rdata + i), str, size)) return pSection->VirtualAddress + i;

    return -1;
}

size_t searchXref(ZydisDecoder* decoder, size_t base, PIMAGE_AMD64_RUNTIME_FUNCTION_ENTRY func, size_t target)
{
    size_t IP = base + func->BeginAddress;
    ZyanUSize length = func->EndAddress - func->BeginAddress;
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

PIMAGE_AMD64_RUNTIME_FUNCTION_ENTRY backtrace(size_t base, PIMAGE_AMD64_RUNTIME_FUNCTION_ENTRY func) {
    if (func->UnwindData & RUNTIME_FUNCTION_INDIRECT)
        func = (PIMAGE_AMD64_RUNTIME_FUNCTION_ENTRY)(base + func->UnwindData & ~3);

    auto unwindInfo = (PUNWIND_INFO)(base + func->UnwindData);
    while (unwindInfo->Flags & UNW_FLAG_CHAININFO)
    {
        func = (PIMAGE_AMD64_RUNTIME_FUNCTION_ENTRY) & (unwindInfo->UnwindCode[(unwindInfo->CountOfCodes + 1) & ~1]);
        unwindInfo = (PUNWIND_INFO)(base + func->UnwindData);
    }

    return func;
}

PIMAGE_IMPORT_DESCRIPTOR findImportImage(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, size_t base, LPCSTR str) {
    while (pImportDescriptor->Name)
    {
        if(!lstrcmpiA((LPCSTR)(base + pImportDescriptor->Name), str)) return pImportDescriptor;
        pImportDescriptor++; 
    }
    return NULL;
}

size_t findImportFunction(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, size_t base, LPCSTR str) {
    auto pThunk = (PIMAGE_THUNK_DATA64)(pImportDescriptor->OriginalFirstThunk + base);
    while (pThunk->u1.AddressOfData)
    {
        if (!lstrcmpiA(((PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + base))->Name, str))
            return (size_t)pThunk - base - pImportDescriptor->OriginalFirstThunk + pImportDescriptor->FirstThunk;
        pThunk++;
    }
    return 0;
}

size_t findImportFunction32(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, size_t base, LPCSTR str) {
    auto pThunk = (PIMAGE_THUNK_DATA32)(pImportDescriptor->OriginalFirstThunk + base);
    while (pThunk->u1.AddressOfData)
    {
        if (!lstrcmpiA(((PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + base))->Name, str))
            return (size_t)pThunk - base - pImportDescriptor->OriginalFirstThunk + pImportDescriptor->FirstThunk;
        pThunk++;
    }
    return 0;
}

void LocalOnlyPatch(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target);

void DefPolicyPatch(ZydisDecoder* decoder, size_t RVA, size_t base);

int SingleUserPatch(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target, size_t target2);

int main(int argc, char** argv)
{
    char szTermsrv[MAX_PATH + 1];
    if (argc >= 2) lstrcpyA(szTermsrv, argv[1]);
    else lstrcpyA(szTermsrv + GetSystemDirectoryA(szTermsrv, sizeof(szTermsrv) / sizeof(char)), "\\termsrv.dll");
#ifndef _WIN64
    PVOID OldValue;
    Wow64DisableWow64FsRedirection(&OldValue);
#endif // _WIN64
    auto hFile = CreateFileA(szTermsrv, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#ifndef _WIN64
    Wow64RevertWow64FsRedirection(OldValue);
#endif // _WIN64
    if (hFile == INVALID_HANDLE_VALUE) return -1;
    auto hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (!hMap) return -6;
    auto base = (size_t)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) return -7;
    auto pDos = (PIMAGE_DOS_HEADER)base;
    auto pNT = (PIMAGE_NT_HEADERS64)(base + pDos->e_lfanew);
    auto text = findSection(pNT, ".text");
    auto rdata = findSection(pNT, ".rdata");
    if (!rdata) rdata = text;
    
    auto CDefPolicy_Query = pattenMatch(base, rdata, Query, sizeof(Query) - 1);
    auto GetInstanceOfTSLicense = pattenMatch(base, rdata, InstanceOfLicense, sizeof(InstanceOfLicense) - 1);
    auto IsSingleSessionPerUserEnabled = pattenMatch(base, rdata, SingleSessionEnabled, sizeof(SingleSessionEnabled) - 1);
    auto IsSingleSessionPerUser = pattenMatch(base, rdata, "IsSingleSessionPerUser", sizeof("IsSingleSessionPerUser"));
    if (!memcmp((void*)(base + IsSingleSessionPerUser - 8), "CUtils::", 8)) IsSingleSessionPerUser -= 8;
    auto IsLicenseTypeLocalOnly = pattenMatch(base, rdata, LocalOnly, sizeof(LocalOnly) - 1);
    auto bRemoteConnAllowed = pattenMatch(base, rdata, AllowRemote, sizeof(AllowRemote));

    PIMAGE_DATA_DIRECTORY pImportDirectory;
    if (pNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        pImportDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
    else
        pImportDirectory = ((PIMAGE_NT_HEADERS32)pNT)->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
    auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + pImportDirectory->VirtualAddress);
    auto import_msvcrt = findImportImage(pImportDescriptor, base, "msvcrt.dll");
    if (!import_msvcrt) return -2;
    
    size_t memset_addr, VerifyVersion_addr = -1;
    auto import_krnl32 = findImportImage(pImportDescriptor, base, "api-ms-win-core-kernel32-legacy-l1-1-1.dll");
    if (!import_krnl32) import_krnl32 = findImportImage(pImportDescriptor, base, "KERNEL32.dll");
    
    size_t CDefPolicy_Query_addr = 0, GetInstanceOfTSLicense_addr = 0, IsSingleSessionPerUserEnabled_addr = 0,
        IsSingleSessionPerUser_addr = 0, IsLicenseTypeLocalOnly_addr = 0, bRemoteConnAllowed_xref;
    DWORD CSLQuery_Initialize_addr = 0, CSLQuery_Initialize_len = 0x11000;

    size_t ImageBase, IP, length;
    const char* arch = "x64";
    ZydisDecoder decoder;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (pNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        memset_addr = findImportFunction(import_msvcrt, base, "memset");
        if (import_krnl32) VerifyVersion_addr = findImportFunction(import_krnl32, base, "VerifyVersionInfoW");

        auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
        auto FunctionTable = (PIMAGE_AMD64_RUNTIME_FUNCTION_ENTRY)(base + pExceptionDirectory->VirtualAddress);
        auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(IMAGE_AMD64_RUNTIME_FUNCTION_ENTRY);
        if (!FunctionTableSize) return -3;

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
            else if (!CSLQuery_Initialize_addr && (bRemoteConnAllowed_xref = searchXref(&decoder, base, FunctionTable + i, bRemoteConnAllowed))) {
                auto CSLQuery_Initialize_func = backtrace(base, FunctionTable + i);
                CSLQuery_Initialize_addr = CSLQuery_Initialize_func->BeginAddress;
                CSLQuery_Initialize_len = CSLQuery_Initialize_func->EndAddress - CSLQuery_Initialize_func->BeginAddress;
            }
            if (CDefPolicy_Query_addr && GetInstanceOfTSLicense_addr && IsSingleSessionPerUserEnabled_addr &&
                IsSingleSessionPerUser_addr && IsLicenseTypeLocalOnly_addr && CSLQuery_Initialize_addr) break;
        }
    }
    else {
        ImageBase = ((PIMAGE_NT_HEADERS32)pNT)->OptionalHeader.ImageBase;
        memset_addr = findImportFunction32(import_msvcrt, base, "memset") + ImageBase;
        if (import_krnl32) VerifyVersion_addr = findImportFunction32(import_krnl32, base, "VerifyVersionInfoW") + ImageBase;

        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
        arch = "x86";
        range visited;
        std::priority_queue<size_t, std::vector<size_t>, std::greater<size_t>> jmpAddr;

        IP = base + text->VirtualAddress;
        length = text->SizeOfRawData;

        while (length >= 5)
            if (!memcmp((void*)IP, "\x8B\xFF\x55\x8B\xEC", 5)) {
                jmpAddr.push(IP);

                while (!jmpAddr.empty()) {
                    auto addr = jmpAddr.top();
                    jmpAddr.pop();
                    if (visited.in_range(addr)) continue;

                    auto j = addr;
                    ZyanUSize l = text->SizeOfRawData - (j - base);
                    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)j, l, &instruction, operands))) {
                        j += instruction.length;
                        l -= instruction.length;

                        size_t target;
                        if (instruction.length == 5 && instruction.mnemonic == ZYDIS_MNEMONIC_PUSH && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                            target = (size_t)operands[0].imm.value.u - ImageBase;
                        else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                            (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instruction.length == 5 ||
                                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instruction.length >= 7 && operands[0].mem.base == ZYDIS_REGISTER_EBP))
                            target = (size_t)operands[1].imm.value.u - ImageBase;
                        else goto nxt;

                        if (!CDefPolicy_Query_addr && target == CDefPolicy_Query)
                            CDefPolicy_Query_addr = IP - base;
                        else if (!GetInstanceOfTSLicense_addr && target == GetInstanceOfTSLicense)
                            GetInstanceOfTSLicense_addr = IP - base;
                        else if (!IsSingleSessionPerUserEnabled_addr && target == IsSingleSessionPerUserEnabled)
                            IsSingleSessionPerUserEnabled_addr = IP - base;
                        else if (!IsSingleSessionPerUser_addr && target == IsSingleSessionPerUser)
                            IsSingleSessionPerUser_addr = IP - base;
                        else if (!IsLicenseTypeLocalOnly_addr && target == IsLicenseTypeLocalOnly)
                            IsLicenseTypeLocalOnly_addr = IP - base;
                        else if (!CSLQuery_Initialize_addr && target == bRemoteConnAllowed) {
                            bRemoteConnAllowed_xref = j - base;
                            CSLQuery_Initialize_addr = (DWORD)(IP - base);
                        }
                        else goto nxt;
                        if (visited.empty()) visited.add(addr, j);
                        if (CDefPolicy_Query_addr && GetInstanceOfTSLicense_addr && IsSingleSessionPerUserEnabled_addr &&
                            IsSingleSessionPerUser_addr && IsLicenseTypeLocalOnly_addr && CSLQuery_Initialize_addr) goto fin;
                        goto out;

                    nxt:
                        if (instruction.mnemonic >= ZYDIS_MNEMONIC_JB && instruction.mnemonic <= ZYDIS_MNEMONIC_JZ &&
                            instruction.operand_count >= 2 &&
                            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                            operands[0].imm.is_relative == ZYAN_TRUE &&
                            operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            operands[1].reg.value == ZYDIS_REGISTER_EIP) {
                            size_t offset = j + (size_t)operands[0].imm.value.u;
                            if ((offset < addr || offset > j) && !visited.in_range(offset)) jmpAddr.push(offset);
                        }
                        if (instruction.mnemonic == ZYDIS_MNEMONIC_RET || instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
                            visited.add(addr, j);
                            break;
                        }
                    }
                }
            out:
                auto nxt = visited.next_val(IP);
                visited.clear();
                length -= nxt - IP;
                IP = nxt;
            }
            else {
                IP++;
                length--;
            }
    fin:;
    }

    auto hResInfo = FindResourceW((HMODULE)base, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(16));
    if (!hResInfo) return -4;
    auto hResData = (PVS_VERSIONINFO)LoadResource((HMODULE)base, hResInfo);
    if (!hResData) return -5;

    printf("[%hu.%hu.%hu.%hu]\n", HIWORD(hResData->Value.dwFileVersionMS), LOWORD(hResData->Value.dwFileVersionMS),
        HIWORD(hResData->Value.dwFileVersionLS), LOWORD(hResData->Value.dwFileVersionLS));

    if (memset_addr)
    {
        if (IsSingleSessionPerUserEnabled_addr &&
            SingleUserPatch(&decoder, IsSingleSessionPerUserEnabled_addr, base, memset_addr, VerifyVersion_addr));
        else if (IsSingleSessionPerUser_addr)
            if(!SingleUserPatch(&decoder, IsSingleSessionPerUser_addr, base, memset_addr, VerifyVersion_addr))
                puts("ERROR: SingleUserPatch not found");
    }

    if (CDefPolicy_Query_addr)
        DefPolicyPatch(&decoder, CDefPolicy_Query_addr, base);
    else puts("ERROR: CDefPolicy_Query not found");

    if (hResData->Value.dwFileVersionMS <= 0x00060001) return 0;

    if (!CSLQuery_Initialize_addr) {
        puts("ERROR: CSLQuery_Initialize not found");
        return 0;
    }

    IP = base + CSLQuery_Initialize_addr;
    length = CSLQuery_Initialize_len;

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
                (operands[1].reg.value == ZYDIS_REGISTER_RIP ||
                    operands[1].reg.value == ZYDIS_REGISTER_EIP))
            {
                _printf_p("SLPolicyInternal.%1$s=1\n"
                    "SLPolicyOffset.%1$s=%2$zX\n"
                    "SLPolicyFunc.%1$s=New_Win8SL\n", arch, IP + (size_t)operands[0].imm.value.u - base);
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

    _printf_p("SLInitHook.%1$s=1\n"
        "SLInitOffset.%1$s=%2$lX\n"
        "SLInitFunc.%1$s=New_CSLQuery_Initialize\n", arch, CSLQuery_Initialize_addr);

    printf("\n[%hu.%hu.%hu.%hu-SLInit]\n", HIWORD(hResData->Value.dwFileVersionMS), LOWORD(hResData->Value.dwFileVersionMS),
        HIWORD(hResData->Value.dwFileVersionLS), LOWORD(hResData->Value.dwFileVersionLS));

    auto bFUSEnabled = pattenMatch(base, rdata, AllowMultipleSessions, sizeof(AllowMultipleSessions));
    auto bAppServerAllowed = pattenMatch(base, rdata, AllowAppServer, sizeof(AllowAppServer));
    auto bMultimonAllowed = pattenMatch(base, rdata, AllowMultimon, sizeof(AllowMultimon));
    auto lMaxUserSessions = pattenMatch(base, rdata, MaxUserSessions, sizeof(MaxUserSessions));
    auto ulMaxDebugSessions = pattenMatch(base, rdata, MaxDebugSessions, sizeof(MaxDebugSessions));
        
    size_t bServerSku_addr = 0, bRemoteConnAllowed_addr = 0, bFUSEnabled_addr = 0, bAppServerAllowed_addr = 0,
        bMultimonAllowed_addr = 0, lMaxUserSessions_addr = 0, ulMaxDebugSessions_addr = 0, bInitialized_addr = 0;
    auto current = &bServerSku_addr;

    if (decoder.stack_width == ZYDIS_STACK_WIDTH_32) {
        while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)IP, length, &instruction, operands)))
        {
            IP += instruction.length;
            length -= instruction.length;
            if (!*current && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[0].mem.segment == ZYDIS_REGISTER_DS &&
                operands[0].mem.base == ZYDIS_REGISTER_NONE &&
                operands[0].mem.disp.size != 0 &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (operands[1].reg.value == ZYDIS_REGISTER_EAX ||
                    operands[1].reg.value == ZYDIS_REGISTER_EDI ||
                    operands[1].reg.value == ZYDIS_REGISTER_ESI))
                *current = (size_t)operands[0].mem.disp.value - ImageBase;
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[0].mem.segment == ZYDIS_REGISTER_DS &&
                operands[0].mem.base == ZYDIS_REGISTER_NONE &&
                operands[0].mem.disp.size != 0 &&
                operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[1].imm.value.u == 1) {
                bInitialized_addr = (size_t)operands[0].mem.disp.value - ImageBase;
                break;
            }
            else if (instruction.length == 5)
            {
                size_t target;
                if (instruction.mnemonic == ZYDIS_MNEMONIC_PUSH && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                    target = (size_t)operands[0].imm.value.u - ImageBase;
                else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) target = (size_t)operands[1].imm.value.u - ImageBase;
                else continue;

                if (target == bRemoteConnAllowed) current = &bRemoteConnAllowed_addr;
                else if (target == bFUSEnabled) current = &bFUSEnabled_addr;
                else if (target == bAppServerAllowed) current = &bAppServerAllowed_addr;
                else if (target == bMultimonAllowed) current = &bMultimonAllowed_addr;
                else if (target == lMaxUserSessions) current = &lMaxUserSessions_addr;
                else if (target == ulMaxDebugSessions) current = &ulMaxDebugSessions_addr;
            }
        }
    }
    else if (length > 0x100)

        while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)IP, length, &instruction, operands)))
        {
            IP += instruction.length;
            length -= instruction.length;
            if (!*current && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[0].mem.base == ZYDIS_REGISTER_RIP &&
                operands[0].mem.disp.size != 0 &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].reg.value == ZYDIS_REGISTER_EAX)
                *current = (size_t)operands[0].mem.disp.value + IP - base;
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
                operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[1].mem.base == ZYDIS_REGISTER_RIP &&
                operands[1].mem.disp.size != 0 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[0].reg.value == ZYDIS_REGISTER_RCX)
            {
                size_t target = (size_t)operands[1].mem.disp.value + IP - base;
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
                operands[0].mem.disp.size != 0 &&
                operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[1].imm.value.u == 1) {
                bInitialized_addr = (size_t)operands[0].mem.disp.value + IP - base;
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
                IP += (size_t)operands[0].imm.value.u;
            else if (!*current && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[0].mem.base == ZYDIS_REGISTER_RIP &&
                operands[0].mem.disp.size != 0 &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                *current = (size_t)operands[0].mem.disp.value + IP - base;
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
                operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[1].mem.base == ZYDIS_REGISTER_RIP &&
                operands[1].mem.disp.size != 0 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[0].reg.value == ZYDIS_REGISTER_RDX)
            {
                size_t target = (size_t)operands[1].mem.disp.value + IP - base;
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
                operands[0].mem.disp.size != 0 &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (operands[1].reg.value == ZYDIS_REGISTER_EAX ||
                    operands[1].reg.value == ZYDIS_REGISTER_ECX))
                bInitialized_addr = (size_t)operands[0].mem.disp.value + IP - base;
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_RET)
                break;
        }
    }

    if (bServerSku_addr)
        printf("bServerSku.%s=%zX\n", arch, bServerSku_addr);
    else puts("ERROR: bServerSku not found");

    if (bRemoteConnAllowed_addr)
        printf("bRemoteConnAllowed.%s=%zX\n", arch, bRemoteConnAllowed_addr);
    else puts("ERROR: bRemoteConnAllowed not found");

    if (bFUSEnabled_addr)
        printf("bFUSEnabled.%s=%zX\n", arch, bFUSEnabled_addr);
    else puts("ERROR: bFUSEnabled not found");

    if (bAppServerAllowed_addr)
        printf("bAppServerAllowed.%s=%zX\n", arch, bAppServerAllowed_addr);
    else puts("ERROR: bAppServerAllowed not found");

    if (bMultimonAllowed_addr)
        printf("bMultimonAllowed.%s=%zX\n", arch, bMultimonAllowed_addr);
    else puts("ERROR: bMultimonAllowed not found");

    if (lMaxUserSessions_addr)
        printf("lMaxUserSessions.%s=%zX\n", arch, lMaxUserSessions_addr);
    else puts("ERROR: lMaxUserSessions not found");

    if (ulMaxDebugSessions_addr)
        printf("ulMaxDebugSessions.%s=%zX\n", arch, ulMaxDebugSessions_addr);
    else puts("ERROR: ulMaxDebugSessions not found");

    if (bInitialized_addr)
        printf("bInitialized.%s=%zX\n", arch, bInitialized_addr);
    else puts("ERROR: bInitialized not found");

    return 0;
}
