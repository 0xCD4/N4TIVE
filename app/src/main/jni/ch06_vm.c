/*
 * Challenge 06: Custom Virtual Machine
 * Difficulty: 5/5
 *
 * A custom stack-based VM with 32 opcodes and 16 registers.
 * The VM executes a bytecode program that:
 *   1. Takes a 16-byte user input
 *   2. Runs it through arithmetic/bitwise transformations
 *   3. Compares against expected output
 *
 * To solve:
 *   1. Reverse the VM instruction set from the .so
 *   2. Disassemble the bytecode program (encoded_bytecode in .rodata,
 *      also returned by getBytecode())
 *   3. Understand the transformation pipeline
 *   4. Solve the constraint system (use Z3 or manual analysis)
 *   5. Pass the correct 16-byte input to execute(). The flag inner is
 *      the first 20 bytes of SHA-256(input), hex-encoded
 *
 * The bytecode has deliberately confusing features:
 *   - It is XOR-encoded and only decoded at runtime
 *   - Opaque predicates guard branches that are never taken
 *   - Dead blocks that look like they change the registers
 */

#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>
#include "flag_core.h"

#define TAG "ch06"

/* VM Configuration */
#define VM_NUM_REGS    16
#define VM_STACK_SIZE  256
#define VM_MEM_SIZE    4096
#define VM_MAX_STEPS   100000
#define VM_INPUT_LEN   16

/* Opcodes */
enum {
    OP_NOP      = 0x00,
    OP_PUSH     = 0x01,  /* push immediate u32 */
    OP_POP      = 0x02,  /* pop to register */
    OP_LOAD     = 0x03,  /* push register value */
    OP_STORE    = 0x04,  /* pop to register */
    OP_ADD      = 0x05,
    OP_SUB      = 0x06,
    OP_MUL      = 0x07,
    OP_DIV      = 0x08,
    OP_MOD      = 0x09,
    OP_XOR      = 0x0A,
    OP_AND      = 0x0B,
    OP_OR       = 0x0C,
    OP_NOT      = 0x0D,
    OP_SHL      = 0x0E,
    OP_SHR      = 0x0F,
    OP_ROL      = 0x10,  /* rotate left */
    OP_ROR      = 0x11,  /* rotate right */
    OP_CMP      = 0x12,  /* compare, set flags */
    OP_JMP      = 0x13,  /* unconditional jump */
    OP_JEQ      = 0x14,  /* jump if equal */
    OP_JNE      = 0x15,  /* jump if not equal */
    OP_JGT      = 0x16,  /* jump if greater */
    OP_JLT      = 0x17,  /* jump if less */
    OP_CALL     = 0x18,  /* push PC, jump */
    OP_RET      = 0x19,  /* pop to PC */
    OP_MLOAD    = 0x1A,  /* load from memory */
    OP_MSTORE   = 0x1B,  /* store to memory */
    OP_INPUT    = 0x1C,  /* read input byte */
    OP_OUTPUT   = 0x1D,  /* write output byte */
    OP_HALT     = 0x1E,
    OP_SWAP     = 0x1F,  /* swap top two stack values */
};

/* VM State */
typedef struct {
    uint32_t regs[VM_NUM_REGS];
    uint32_t stack[VM_STACK_SIZE];
    uint8_t  memory[VM_MEM_SIZE];
    int      sp;            /* stack pointer */
    int      pc;            /* program counter */
    int      cmp_flag;      /* comparison result: -1, 0, 1 */
    int      halted;
    int      steps;

    /* I/O */
    const uint8_t *input;
    int            input_pos;
    int            input_len;
    uint8_t       *output;
    int            output_pos;
    int            output_max;
} vm_state;

/* Push/pop helpers */
static int vm_push(vm_state *vm, uint32_t val) {
    if (vm->sp >= VM_STACK_SIZE) return -1;
    vm->stack[vm->sp++] = val;
    return 0;
}

static int vm_pop(vm_state *vm, uint32_t *val) {
    if (vm->sp <= 0) return -1;
    *val = vm->stack[--vm->sp];
    return 0;
}

/* Read u32 from bytecode (little-endian) */
static uint32_t read_u32(const uint8_t *code, int *pc) {
    uint32_t val = (uint32_t)code[*pc] |
                   ((uint32_t)code[*pc + 1] << 8) |
                   ((uint32_t)code[*pc + 2] << 16) |
                   ((uint32_t)code[*pc + 3] << 24);
    *pc += 4;
    return val;
}

/* Execute one instruction */
static int vm_step(vm_state *vm, const uint8_t *code, int code_len) {
    if (vm->halted || vm->pc >= code_len) return -1;
    if (vm->steps++ > VM_MAX_STEPS) { vm->halted = 1; return -2; }

    uint8_t op = code[vm->pc++];
    uint32_t a, b, imm;
    uint8_t reg;

    switch (op) {
    case OP_NOP:
        break;

    case OP_PUSH:
        imm = read_u32(code, &vm->pc);
        vm_push(vm, imm);
        break;

    case OP_POP:
        reg = code[vm->pc++];
        if (reg < VM_NUM_REGS) vm_pop(vm, &vm->regs[reg]);
        break;

    case OP_LOAD:
        reg = code[vm->pc++];
        if (reg < VM_NUM_REGS) vm_push(vm, vm->regs[reg]);
        break;

    case OP_STORE:
        reg = code[vm->pc++];
        if (reg < VM_NUM_REGS) vm_pop(vm, &vm->regs[reg]);
        break;

    case OP_ADD:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, a + b);
        break;

    case OP_SUB:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, a - b);
        break;

    case OP_MUL:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, a * b);
        break;

    case OP_DIV:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, b ? a / b : 0);
        break;

    case OP_MOD:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, b ? a % b : 0);
        break;

    case OP_XOR:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, a ^ b);
        break;

    case OP_AND:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, a & b);
        break;

    case OP_OR:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, a | b);
        break;

    case OP_NOT:
        vm_pop(vm, &a);
        vm_push(vm, ~a);
        break;

    case OP_SHL:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, a << (b & 31));
        break;

    case OP_SHR:
        vm_pop(vm, &b); vm_pop(vm, &a);
        vm_push(vm, a >> (b & 31));
        break;

    case OP_ROL:
        vm_pop(vm, &b); vm_pop(vm, &a);
        b &= 31;
        /* a shift by 32 is undefined in C, so rotate by 0 is special-cased */
        vm_push(vm, b ? (a << b) | (a >> (32 - b)) : a);
        break;

    case OP_ROR:
        vm_pop(vm, &b); vm_pop(vm, &a);
        b &= 31;
        vm_push(vm, b ? (a >> b) | (a << (32 - b)) : a);
        break;

    case OP_CMP:
        vm_pop(vm, &b); vm_pop(vm, &a);
        if (a < b) vm->cmp_flag = -1;
        else if (a > b) vm->cmp_flag = 1;
        else vm->cmp_flag = 0;
        break;

    case OP_JMP:
        imm = read_u32(code, &vm->pc);
        vm->pc = (int)imm;
        break;

    case OP_JEQ:
        imm = read_u32(code, &vm->pc);
        if (vm->cmp_flag == 0) vm->pc = (int)imm;
        break;

    case OP_JNE:
        imm = read_u32(code, &vm->pc);
        if (vm->cmp_flag != 0) vm->pc = (int)imm;
        break;

    case OP_JGT:
        imm = read_u32(code, &vm->pc);
        if (vm->cmp_flag > 0) vm->pc = (int)imm;
        break;

    case OP_JLT:
        imm = read_u32(code, &vm->pc);
        if (vm->cmp_flag < 0) vm->pc = (int)imm;
        break;

    case OP_CALL:
        imm = read_u32(code, &vm->pc);
        vm_push(vm, (uint32_t)vm->pc);
        vm->pc = (int)imm;
        break;

    case OP_RET:
        vm_pop(vm, &a);
        vm->pc = (int)a;
        break;

    case OP_MLOAD:
        vm_pop(vm, &a);
        if (a < VM_MEM_SIZE - 3) {
            uint32_t val = (uint32_t)vm->memory[a] |
                           ((uint32_t)vm->memory[a+1] << 8) |
                           ((uint32_t)vm->memory[a+2] << 16) |
                           ((uint32_t)vm->memory[a+3] << 24);
            vm_push(vm, val);
        }
        break;

    case OP_MSTORE:
        vm_pop(vm, &b); /* address */
        vm_pop(vm, &a); /* value */
        if (b < VM_MEM_SIZE - 3) {
            vm->memory[b]     = (uint8_t)(a);
            vm->memory[b + 1] = (uint8_t)(a >> 8);
            vm->memory[b + 2] = (uint8_t)(a >> 16);
            vm->memory[b + 3] = (uint8_t)(a >> 24);
        }
        break;

    case OP_INPUT:
        if (vm->input_pos < vm->input_len) {
            vm_push(vm, (uint32_t)vm->input[vm->input_pos++]);
        } else {
            vm_push(vm, 0);
        }
        break;

    case OP_OUTPUT:
        vm_pop(vm, &a);
        if (vm->output && vm->output_pos < vm->output_max) {
            vm->output[vm->output_pos++] = (uint8_t)(a & 0xFF);
        }
        break;

    case OP_HALT:
        vm->halted = 1;
        break;

    case OP_SWAP:
        if (vm->sp >= 2) {
            uint32_t tmp = vm->stack[vm->sp - 1];
            vm->stack[vm->sp - 1] = vm->stack[vm->sp - 2];
            vm->stack[vm->sp - 2] = tmp;
        }
        break;

    default:
        /* Invalid opcode -- halt */
        vm->halted = 1;
        return -3;
    }

    return 0;
}

/*
 * The bytecode program (XOR-encoded with BYTECODE_XOR_KEY for obfuscation).
 * At runtime, decoded into a local buffer before execution.
 *
 * The program logic (when decoded):
 *   1. Read 16 input bytes into registers R0-R15
 *   2. Apply a series of transformations:
 *      - Pair-wise XOR: R0^=R1, R2^=R3, etc.
 *      - Rotate each register left by (index + 1)
 *      - Add a constant round key to each register
 *      - Cross-mix, in order: R[i] += R[(i+7)%16]
 *   3. Compare each register against an expected constant
 *   4. If all match, output the success marker 1, otherwise 0
 *
 * Every step is a bijection on the register state and the inputs are
 * single bytes, so at most one 16-byte input passes.
 *
 * Written by scripts/gen_flags.py. Do not edit by hand. The comment on
 * each row shows the decoded offset and instructions.
 */
/* gen_flags begin encoded_bytecode */
static const uint8_t encoded_bytecode[] = {
    /* 0000  INPUT; STORE R0 */
    0x46, 0x5E, 0x5A,
    /* 0003  INPUT; STORE R1 */
    0x46, 0x5E, 0x5B,
    /* 0006  INPUT; STORE R2 */
    0x46, 0x5E, 0x58,
    /* 0009  INPUT; STORE R3 */
    0x46, 0x5E, 0x59,
    /* 000C  INPUT; STORE R4 */
    0x46, 0x5E, 0x5E,
    /* 000F  INPUT; STORE R5 */
    0x46, 0x5E, 0x5F,
    /* 0012  INPUT; STORE R6 */
    0x46, 0x5E, 0x5C,
    /* 0015  INPUT; STORE R7 */
    0x46, 0x5E, 0x5D,
    /* 0018  INPUT; STORE R8 */
    0x46, 0x5E, 0x52,
    /* 001B  INPUT; STORE R9 */
    0x46, 0x5E, 0x53,
    /* 001E  INPUT; STORE R10 */
    0x46, 0x5E, 0x50,
    /* 0021  INPUT; STORE R11 */
    0x46, 0x5E, 0x51,
    /* 0024  INPUT; STORE R12 */
    0x46, 0x5E, 0x56,
    /* 0027  INPUT; STORE R13 */
    0x46, 0x5E, 0x57,
    /* 002A  INPUT; STORE R14 */
    0x46, 0x5E, 0x54,
    /* 002D  INPUT; STORE R15 */
    0x46, 0x5E, 0x55,
    /* 0030  PUSH 0x7A3C91E5; PUSH 0x7A3C91E5; CMP; JNE 02D9 */
    0x5B, 0xBF, 0xCB, 0x66, 0x20, 0x5B, 0xBF, 0xCB, 0x66, 0x20, 0x48, 0x4F,
    0x83, 0x58, 0x5A, 0x5A,
    /* 0040  LOAD R0; LOAD R1; XOR; STORE R0 */
    0x59, 0x5A, 0x59, 0x5B, 0x50, 0x5E, 0x5A,
    /* 0047  LOAD R2; LOAD R3; XOR; STORE R2 */
    0x59, 0x58, 0x59, 0x59, 0x50, 0x5E, 0x58,
    /* 004E  LOAD R4; LOAD R5; XOR; STORE R4 */
    0x59, 0x5E, 0x59, 0x5F, 0x50, 0x5E, 0x5E,
    /* 0055  LOAD R6; LOAD R7; XOR; STORE R6 */
    0x59, 0x5C, 0x59, 0x5D, 0x50, 0x5E, 0x5C,
    /* 005C  LOAD R8; LOAD R9; XOR; STORE R8 */
    0x59, 0x52, 0x59, 0x53, 0x50, 0x5E, 0x52,
    /* 0063  LOAD R10; LOAD R11; XOR; STORE R10 */
    0x59, 0x50, 0x59, 0x51, 0x50, 0x5E, 0x50,
    /* 006A  LOAD R12; LOAD R13; XOR; STORE R12 */
    0x59, 0x56, 0x59, 0x57, 0x50, 0x5E, 0x56,
    /* 0071  LOAD R14; LOAD R15; XOR; STORE R14 */
    0x59, 0x54, 0x59, 0x55, 0x50, 0x5E, 0x54,
    /* 0078  LOAD R0; PUSH 0x1; ROL; PUSH 0xBD4F7B2A; ADD; STORE R0 */
    0x59, 0x5A, 0x5B, 0x5B, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x70, 0x21, 0x15,
    0xE7, 0x5F, 0x5E, 0x5A,
    /* 0088  LOAD R1; PUSH 0x2; ROL; PUSH 0x1D87DA8; ADD; STORE R1 */
    0x59, 0x5B, 0x5B, 0x58, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0xF2, 0x27, 0x82,
    0x5B, 0x5F, 0x5E, 0x5B,
    /* 0098  LOAD R2; PUSH 0x3; ROL; PUSH 0x45DE8211; ADD; STORE R2 */
    0x59, 0x58, 0x5B, 0x59, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x4B, 0xD8, 0x84,
    0x1F, 0x5F, 0x5E, 0x58,
    /* 00A8  LOAD R3; PUSH 0x4; ROL; PUSH 0x43616215; ADD; STORE R3 */
    0x59, 0x59, 0x5B, 0x5E, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x4F, 0x38, 0x3B,
    0x19, 0x5F, 0x5E, 0x59,
    /* 00B8  LOAD R4; PUSH 0x5; ROL; PUSH 0x81EB07D4; ADD; STORE R4 */
    0x59, 0x5E, 0x5B, 0x5F, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x8E, 0x5D, 0xB1,
    0xDB, 0x5F, 0x5E, 0x5E,
    /* 00C8  LOAD R5; PUSH 0x6; ROL; PUSH 0x46BBFDB2; ADD; STORE R5 */
    0x59, 0x5F, 0x5B, 0x5C, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0xE8, 0xA7, 0xE1,
    0x1C, 0x5F, 0x5E, 0x5F,
    /* 00D8  LOAD R6; PUSH 0x7; ROL; PUSH 0x480F5531; ADD; STORE R6 */
    0x59, 0x5C, 0x5B, 0x5D, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x6B, 0x0F, 0x55,
    0x12, 0x5F, 0x5E, 0x5C,
    /* 00E8  LOAD R7; PUSH 0x8; ROL; PUSH 0xB0466EC4; ADD; STORE R7 */
    0x59, 0x5D, 0x5B, 0x52, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x9E, 0x34, 0x1C,
    0xEA, 0x5F, 0x5E, 0x5D,
    /* 00F8  LOAD R8; PUSH 0x9; ROL; PUSH 0xA0D0B8C6; ADD; STORE R8 */
    0x59, 0x52, 0x5B, 0x53, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x9C, 0xE2, 0x8A,
    0xFA, 0x5F, 0x5E, 0x52,
    /* 0108  LOAD R9; PUSH 0xA; ROL; PUSH 0x2F678FA; ADD; STORE R9 */
    0x59, 0x53, 0x5B, 0x50, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0xA0, 0x22, 0xAC,
    0x58, 0x5F, 0x5E, 0x53,
    /* 0118  LOAD R10; PUSH 0xB; ROL; PUSH 0xC3E8F0AA; ADD; STORE R10 */
    0x59, 0x50, 0x5B, 0x51, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0xF0, 0xAA, 0xB2,
    0x99, 0x5F, 0x5E, 0x50,
    /* 0128  LOAD R11; PUSH 0xC; ROL; PUSH 0x9DB5C52C; ADD; STORE R11 */
    0x59, 0x51, 0x5B, 0x56, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x76, 0x9F, 0xEF,
    0xC7, 0x5F, 0x5E, 0x51,
    /* 0138  LOAD R12; PUSH 0xD; ROL; PUSH 0x6461D9FF; ADD; STORE R12 */
    0x59, 0x56, 0x5B, 0x57, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0xA5, 0x83, 0x3B,
    0x3E, 0x5F, 0x5E, 0x56,
    /* 0148  LOAD R13; PUSH 0xE; ROL; PUSH 0x45FD4F10; ADD; STORE R13 */
    0x59, 0x57, 0x5B, 0x54, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x4A, 0x15, 0xA7,
    0x1F, 0x5F, 0x5E, 0x57,
    /* 0158  LOAD R14; PUSH 0xF; ROL; PUSH 0xC1F94AE7; ADD; STORE R14 */
    0x59, 0x54, 0x5B, 0x55, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0xBD, 0x10, 0xA3,
    0x9B, 0x5F, 0x5E, 0x54,
    /* 0168  LOAD R15; PUSH 0x10; ROL; PUSH 0xF69E45DD; ADD; STORE R15 */
    0x59, 0x55, 0x5B, 0x4A, 0x5A, 0x5A, 0x5A, 0x4A, 0x5B, 0x87, 0x1F, 0xC4,
    0xAC, 0x5F, 0x5E, 0x55,
    /* 0178  LOAD R3; PUSH 0x1; OR; PUSH 0x0; CMP; JEQ 02E3 */
    0x59, 0x59, 0x5B, 0x5B, 0x5A, 0x5A, 0x5A, 0x56, 0x5B, 0x5A, 0x5A, 0x5A,
    0x5A, 0x48, 0x4E, 0xB9, 0x58, 0x5A, 0x5A,
    /* 018B  LOAD R0; LOAD R7; ADD; STORE R0 */
    0x59, 0x5A, 0x59, 0x5D, 0x5F, 0x5E, 0x5A,
    /* 0192  LOAD R1; LOAD R8; ADD; STORE R1 */
    0x59, 0x5B, 0x59, 0x52, 0x5F, 0x5E, 0x5B,
    /* 0199  LOAD R2; LOAD R9; ADD; STORE R2 */
    0x59, 0x58, 0x59, 0x53, 0x5F, 0x5E, 0x58,
    /* 01A0  LOAD R3; LOAD R10; ADD; STORE R3 */
    0x59, 0x59, 0x59, 0x50, 0x5F, 0x5E, 0x59,
    /* 01A7  LOAD R4; LOAD R11; ADD; STORE R4 */
    0x59, 0x5E, 0x59, 0x51, 0x5F, 0x5E, 0x5E,
    /* 01AE  LOAD R5; LOAD R12; ADD; STORE R5 */
    0x59, 0x5F, 0x59, 0x56, 0x5F, 0x5E, 0x5F,
    /* 01B5  LOAD R6; LOAD R13; ADD; STORE R6 */
    0x59, 0x5C, 0x59, 0x57, 0x5F, 0x5E, 0x5C,
    /* 01BC  LOAD R7; LOAD R14; ADD; STORE R7 */
    0x59, 0x5D, 0x59, 0x54, 0x5F, 0x5E, 0x5D,
    /* 01C3  LOAD R8; LOAD R15; ADD; STORE R8 */
    0x59, 0x52, 0x59, 0x55, 0x5F, 0x5E, 0x52,
    /* 01CA  LOAD R9; LOAD R0; ADD; STORE R9 */
    0x59, 0x53, 0x59, 0x5A, 0x5F, 0x5E, 0x53,
    /* 01D1  LOAD R10; LOAD R1; ADD; STORE R10 */
    0x59, 0x50, 0x59, 0x5B, 0x5F, 0x5E, 0x50,
    /* 01D8  LOAD R11; LOAD R2; ADD; STORE R11 */
    0x59, 0x51, 0x59, 0x58, 0x5F, 0x5E, 0x51,
    /* 01DF  LOAD R12; LOAD R3; ADD; STORE R12 */
    0x59, 0x56, 0x59, 0x59, 0x5F, 0x5E, 0x56,
    /* 01E6  LOAD R13; LOAD R4; ADD; STORE R13 */
    0x59, 0x57, 0x59, 0x5E, 0x5F, 0x5E, 0x57,
    /* 01ED  LOAD R14; LOAD R5; ADD; STORE R14 */
    0x59, 0x54, 0x59, 0x5F, 0x5F, 0x5E, 0x54,
    /* 01F4  LOAD R15; LOAD R6; ADD; STORE R15 */
    0x59, 0x55, 0x59, 0x5C, 0x5F, 0x5E, 0x55,
    /* 01FB  LOAD R0; PUSH 0x6D966E9A; CMP; JNE 02D2 */
    0x59, 0x5A, 0x5B, 0xC0, 0x34, 0xCC, 0x37, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 0208  LOAD R1; PUSH 0xA2AA4DE6; CMP; JNE 02D2 */
    0x59, 0x5B, 0x5B, 0xBC, 0x17, 0xF0, 0xF8, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 0215  LOAD R2; PUSH 0x48D73C1B; CMP; JNE 02D2 */
    0x59, 0x58, 0x5B, 0x41, 0x66, 0x8D, 0x12, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 0222  LOAD R3; PUSH 0x74F81CF; CMP; JNE 02D2 */
    0x59, 0x59, 0x5B, 0x95, 0xDB, 0x15, 0x5D, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 022F  LOAD R4; PUSH 0x1FA78180; CMP; JNE 02D2 */
    0x59, 0x5E, 0x5B, 0xDA, 0xDB, 0xFD, 0x45, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 023C  LOAD R5; PUSH 0xAB3CC871; CMP; JNE 02D2 */
    0x59, 0x5F, 0x5B, 0x2B, 0x92, 0x66, 0xF1, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 0249  LOAD R6; PUSH 0x8E1E49C1; CMP; JNE 02D2 */
    0x59, 0x5C, 0x5B, 0x9B, 0x13, 0x44, 0xD4, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 0256  LOAD R7; PUSH 0x72BDBCAB; CMP; JNE 02D2 */
    0x59, 0x5D, 0x5B, 0xF1, 0xE6, 0xE7, 0x28, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 0263  LOAD R8; PUSH 0x984214A3; CMP; JNE 02D2 */
    0x59, 0x52, 0x5B, 0xF9, 0x4E, 0x18, 0xC2, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 0270  LOAD R9; PUSH 0x708F2394; CMP; JNE 02D2 */
    0x59, 0x53, 0x5B, 0xCE, 0x79, 0xD5, 0x2A, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 027D  LOAD R10; PUSH 0x66985E90; CMP; JNE 02D2 */
    0x59, 0x50, 0x5B, 0xCA, 0x04, 0xC2, 0x3C, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 028A  LOAD R11; PUSH 0xE693A147; CMP; JNE 02D2 */
    0x59, 0x51, 0x5B, 0x1D, 0xFB, 0xC9, 0xBC, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 0297  LOAD R12; PUSH 0x6BD01BCE; CMP; JNE 02D2 */
    0x59, 0x56, 0x5B, 0x94, 0x41, 0x8A, 0x31, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 02A4  LOAD R13; PUSH 0x65B61090; CMP; JNE 02D2 */
    0x59, 0x57, 0x5B, 0xCA, 0x4A, 0xEC, 0x3F, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 02B1  LOAD R14; PUSH 0x6DB39358; CMP; JNE 02D2 */
    0x59, 0x54, 0x5B, 0x02, 0xC9, 0xE9, 0x37, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 02BE  LOAD R15; PUSH 0x858E8F9E; CMP; JNE 02D2 */
    0x59, 0x55, 0x5B, 0xC4, 0xD5, 0xD4, 0xDF, 0x48, 0x4F, 0x88, 0x58, 0x5A,
    0x5A,
    /* 02CB  PUSH 0x1; OUTPUT; HALT */
    0x5B, 0x5B, 0x5A, 0x5A, 0x5A, 0x47, 0x44,
    /* 02D2  PUSH 0x0; OUTPUT; HALT */
    0x5B, 0x5A, 0x5A, 0x5A, 0x5A, 0x47, 0x44,
    /* 02D9  LOAD R0; NOT; STORE R0; JMP 0040 */
    0x59, 0x5A, 0x57, 0x5E, 0x5A, 0x49, 0x1A, 0x5A, 0x5A, 0x5A,
    /* 02E3  PUSH 0xDEADC0DE; STORE R5; JMP 018B */
    0x5B, 0x84, 0x9A, 0xF7, 0x84, 0x5E, 0x5F, 0x49, 0xD1, 0x5B, 0x5A, 0x5A,
};
/* gen_flags end encoded_bytecode */

#define BYTECODE_XOR_KEY 0x5A
#define BYTECODE_SIZE sizeof(encoded_bytecode)

/* Decode bytecode at runtime */
static void decode_bytecode(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = encoded_bytecode[i] ^ BYTECODE_XOR_KEY;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_ctf_nativectf_challenges_Ch06_execute(JNIEnv *env, jobject obj,
                                                 jbyteArray input) {
    (void)obj;
    vm_state vm;
    uint8_t bytecode[BYTECODE_SIZE];
    uint8_t output_buf[64];
    uint8_t input_copy[VM_INPUT_LEN];
    int success = 0;

    memset(&vm, 0, sizeof(vm));
    memset(output_buf, 0, sizeof(output_buf));

    /*
     * The program consumes exactly VM_INPUT_LEN bytes. They are copied
     * out of the Java array, so nothing reads the array after this call.
     */
    if (input && (*env)->GetArrayLength(env, input) == VM_INPUT_LEN) {
        (*env)->GetByteArrayRegion(env, input, 0, VM_INPUT_LEN,
                                   (jbyte *)input_copy);

        /* Decode bytecode */
        decode_bytecode(bytecode, BYTECODE_SIZE);

        /* Setup I/O */
        vm.input = input_copy;
        vm.input_len = VM_INPUT_LEN;
        vm.input_pos = 0;
        vm.output = output_buf;
        vm.output_pos = 0;
        vm.output_max = sizeof(output_buf);

        /* Execute */
        while (!vm.halted && vm.pc < (int)BYTECODE_SIZE) {
            if (vm_step(&vm, bytecode, (int)BYTECODE_SIZE) < 0) break;
        }

        success = (vm.output_pos > 0 && output_buf[0] == 1);
    }

    if (success) {
        /*
         * Correct input found. The flag is derived from the input, so it
         * is not stored anywhere in the library:
         *   FLAG{ hex(SHA-256(input)[0..19]) }
         */
        char flag_buf[128];
        char hex_part[64];
        uint8_t hash[SHA256_DIGEST_SIZE];

        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, input_copy, VM_INPUT_LEN);
        sha256_final(&ctx, hash);

        bytes_to_hex(hash, 20, hex_part);

        snprintf(flag_buf, sizeof(flag_buf), "FLAG{%s}", hex_part);

        jbyteArray result = (*env)->NewByteArray(env, (jsize)strlen(flag_buf));
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)strlen(flag_buf),
                                    (jbyte *)flag_buf);
        return result;
    }

    /* Wrong input */
    const char *fail_msg = "WRONG_INPUT";
    jbyteArray result = (*env)->NewByteArray(env, (jsize)strlen(fail_msg));
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)strlen(fail_msg),
                                (jbyte *)fail_msg);
    return result;
}

/* Get the raw encoded bytecode for offline analysis */
JNIEXPORT jbyteArray JNICALL
Java_com_ctf_nativectf_challenges_Ch06_getBytecode(JNIEnv *env, jobject obj) {
    (void)obj;
    jbyteArray result = (*env)->NewByteArray(env, (jsize)BYTECODE_SIZE);
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)BYTECODE_SIZE,
                                (jbyte *)encoded_bytecode);
    return result;
}

/* Get the XOR key as a hint */
JNIEXPORT jint JNICALL
Java_com_ctf_nativectf_challenges_Ch06_getEncodingHint(JNIEnv *env, jobject obj) {
    (void)env; (void)obj;
    /* In the stripped build, this is the only hint about the encoding */
    return (jint)BYTECODE_XOR_KEY;
}

JNIEXPORT jboolean JNICALL
Java_com_ctf_nativectf_challenges_Ch06_verifyFlag(JNIEnv *env, jobject obj,
                                                    jstring input) {
    (void)obj;
    const char *str = (*env)->GetStringUTFChars(env, input, NULL);
    if (!str) return JNI_FALSE;

    int result = verify_flag(5, str);

    (*env)->ReleaseStringUTFChars(env, input, str);
    return result ? JNI_TRUE : JNI_FALSE;
}
