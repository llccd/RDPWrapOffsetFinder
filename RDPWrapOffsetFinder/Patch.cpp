#include <iostream>
#include <windows.h>
#include <Zydis/Zydis.h>

void LocalOnlyPatch(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target) {
    ZyanUSize length = 256;
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
            while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)) && instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
                IP += instruction.length;
                length -= instruction.length;
            }
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
                IP = target + (size_t)operands[0].imm.value.u;
            }
            else if (instruction.mnemonic != ZYDIS_MNEMONIC_JS) break;
            else
            {
                IP += instruction.length;
                target = IP + (size_t)operands[0].imm.value.u;
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
                "LocalOnlyOffset.x64=%zX\n"
                "LocalOnlyCode.x64=%s\n"
                : "LocalOnlyPatch.x86=1\n"
                "LocalOnlyOffset.x86=%zX\n"
                "LocalOnlyCode.x86=%s\n", IP - base, jmp);
            return;
        }
    }
    puts("ERROR: LocalOnlyPatch patten not found");
}

void DefPolicyPatch(ZydisDecoder* decoder, size_t RVA, size_t base) {
    ZyanUSize length = 128;
    ZyanUSize lastLength = 0;
    ZyanUSize instLength;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    auto IP = RVA + base;
    auto mov_base = ZYDIS_REGISTER_NONE;
    auto mov_target = ZYDIS_REGISTER_NONE;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
    {
        instLength = instruction.length;
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

            if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)(IP + instLength), length - instLength, &instruction)))
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
                "DefPolicyOffset.x64=%zX\n"
                "DefPolicyCode.x64=CDefPolicy_Query_%s_%s%s\n"
                : "DefPolicyPatch.x86=1\n"
                "DefPolicyOffset.x86=%zX\n"
                "DefPolicyCode.x86=CDefPolicy_Query_%s_%s%s\n", IP - base, reg1, reg2, jmp);
            return;
        }
        else if (decoder->stack_width == ZYDIS_STACK_WIDTH_64 &&
            !mov_base && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[1].mem.disp.value == 0x63c)
        {
            mov_base = operands[1].mem.base;
            mov_target = operands[0].reg.value;
        }
        else if (decoder->stack_width == ZYDIS_STACK_WIDTH_64 &&
            instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[1].mem.base == mov_base &&
            operands[1].mem.disp.value == 0x638)
        {
            auto mov_target2 = operands[0].reg.value;
            const char* reg1 = ZydisRegisterGetString(mov_target2);
            const char* reg2 = ZydisRegisterGetString(operands[1].mem.base);
            const char* jmp = "";

            auto offset = instLength;
            while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)(IP + offset), length - offset, &instruction, operands))) {
                offset += instruction.length;
                if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
                    operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (operands[0].reg.value == mov_target && operands[1].reg.value == mov_target2 ||
                        operands[0].reg.value == mov_target2 && operands[1].reg.value == mov_target))
                    break;
            }

            if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)(IP + offset), length - offset, &instruction)))
                break;

            if (instruction.mnemonic == ZYDIS_MNEMONIC_JNZ)
            {
                IP -= lastLength;
                jmp = "_jmp";
            }
            else if (instruction.mnemonic != ZYDIS_MNEMONIC_JZ && instruction.mnemonic != ZYDIS_MNEMONIC_POP)
                break;

            printf("DefPolicyPatch.x64=1\n"
                "DefPolicyOffset.x64=%zX\n"
                "DefPolicyCode.x64=CDefPolicy_Query_%s_%s%s\n", IP - base, reg1, reg2, jmp);
            return;
        }
    out:
        IP += instLength;
        length -= instLength;
        lastLength = instLength;
    }
    puts("ERROR: DefPolicyPatch patten not found");
}

int SingleUserPatch(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target, size_t target2) {
    ZyanUSize length = 256;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    auto IP = RVA + base;
    target += base;
    target2 += base;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
    {
        IP += instruction.length;
        length -= instruction.length;
        if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            operands[0].imm.is_relative == ZYAN_TRUE &&
            operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            (operands[1].reg.value == ZYDIS_REGISTER_RIP ||
                operands[1].reg.value == ZYDIS_REGISTER_EIP))
        {
#ifdef MEMSET_DIRECT
            if (target != IP + operands[0].imm.value.u) continue;
#else
            auto jmp_addr = IP + operands[0].imm.value.u;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)jmp_addr, length, &instruction, operands)) ||
                instruction.mnemonic != ZYDIS_MNEMONIC_JMP ||
                operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
                continue;
            if (!(operands[0].mem.base == ZYDIS_REGISTER_RIP &&
                operands[1].reg.value == ZYDIS_REGISTER_RIP &&
                operands[0].mem.disp.value + jmp_addr + instruction.length == target ||
                operands[0].mem.segment == ZYDIS_REGISTER_DS &&
                operands[1].reg.value == ZYDIS_REGISTER_EIP &&
                operands[0].mem.disp.value + base == target))
                continue;
#endif
            while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
            {
                if (decoder->stack_width == ZYDIS_STACK_WIDTH_64) {
                    if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
                        instruction.length >= 5 && instruction.length <= 7 &&
                        operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        operands[0].mem.base == ZYDIS_REGISTER_RIP &&
                        operands[0].mem.disp.value + IP + instruction.length == target2) {
                        printf("SingleUserPatch.x64=1\n"
                            "SingleUserOffset.x64=%zX\n"
                            "SingleUserCode.x64=mov_eax_1_nop_%d\n", IP - base, instruction.length - 5);
                        return 1;
                    }
                    if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
                        instruction.length <= 8 && operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        (operands[0].mem.base == ZYDIS_REGISTER_RBP || operands[0].mem.base == ZYDIS_REGISTER_RSP) &&
                        (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[1].imm.value.u == 1 ||
                            operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)) {
                        printf("SingleUserPatch.x64=1\n"
                            "SingleUserOffset.x64=%zX\n"
                            "SingleUserCode.x64=nop_%d\n", IP - base, instruction.length);
                        return 1;
                    }
                }
                else {
                    if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
                        instruction.length >= 5 && instruction.length <= 7 &&
                        operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        operands[0].mem.segment == ZYDIS_REGISTER_DS &&
                        operands[0].mem.disp.value + base == target2) {
                        printf("SingleUserPatch.x86=1\n"
                            "SingleUserOffset.x86=%zX\n"
                            "SingleUserCode.x86=pop_eax_add_esp_12_nop_%d\n", IP - base, instruction.length - 4);
                        return 1;
                    }
                    if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP && instruction.length <= 8 &&
                        operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[0].mem.base == ZYDIS_REGISTER_EBP &&
                        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[1].imm.value.u == 1) {
                        printf("SingleUserPatch.x86=1\n"
                            "SingleUserOffset.x86=%zX\n"
                            "SingleUserCode.x86=nop_%d\n", IP - base, instruction.length);
                        return 1;
                    }
                }
                IP += instruction.length;
                length -= instruction.length;
            }
            break;
        }
    }
    return 0;
}