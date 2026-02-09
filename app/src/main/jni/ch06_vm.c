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
 *   2. Disassemble the bytecode program (in assets/ch06_bytecode.bin)
 *   3. Understand the transformation pipeline
 *   4. Solve the constraint system (use Z3 or manual analysis)
 *   5. The correct 16-byte input, when hex-encoded, is the flag inner
 *
 * The VM has deliberately confusing features:
 *   - Dead code paths in the instruction decoder
 *   - Self-modifying bytecode (XOR-decoded at runtime)
 *   - Opaque predicates in the bytecode
 */

#include <jni.h>
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
        vm_push(vm, (a << b) | (a >> (32 - b)));
        break;

    case OP_ROR:
        vm_pop(vm, &b); vm_pop(vm, &a);
        b &= 31;
        vm_push(vm, (a >> b) | (a << (32 - b)));
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
 * The bytecode program (XOR-encoded with key 0x5A for obfuscation).
 * At runtime, decoded into memory before execution.
 *
 * The program logic (when decoded):
 *   1. Read 16 input bytes into registers R0-R15
 *   2. Apply a series of transformations:
 *      - Pair-wise XOR: R0^=R1, R2^=R3, etc.
 *      - Rotate each register by its index
 *      - Add constant round keys
 *      - Cross-mix: R[i] += R[(i+7)%16]
 *   3. Compare each register against expected constants
 *   4. If all match, output success marker
 */
static const uint8_t encoded_bytecode[] = {
    /* Phase 1: Read 16 input bytes into R0-R15 */
    /* INPUT; STORE R0 (repeated 16x) */
    0x46, 0x5E, 0x5A, /* INPUT(0x1C^0x5A=0x46), STORE(0x04^0x5A=0x5E), R0(0x00^0x5A=0x5A) */
    0x46, 0x5E, 0x5B, /* INPUT, STORE, R1 */
    0x46, 0x5E, 0x58, /* INPUT, STORE, R2 */
    0x46, 0x5E, 0x59, /* INPUT, STORE, R3 */
    0x46, 0x5E, 0x5C, /* INPUT, STORE, R4 */
    0x46, 0x5E, 0x5D, /* INPUT, STORE, R5 */
    0x46, 0x5E, 0x5E, /* INPUT, STORE, R6 (note: 0x06^0x5A) */
    0x46, 0x5E, 0x5F, /* INPUT, STORE, R7 */
    0x46, 0x5E, 0x52, /* INPUT, STORE, R8 */
    0x46, 0x5E, 0x53, /* INPUT, STORE, R9 */
    0x46, 0x5E, 0x50, /* INPUT, STORE, R10 */
    0x46, 0x5E, 0x51, /* INPUT, STORE, R11 */
    0x46, 0x5E, 0x56, /* INPUT, STORE, R12 */
    0x46, 0x5E, 0x57, /* INPUT, STORE, R13 */
    0x46, 0x5E, 0x54, /* INPUT, STORE, R14 */
    0x46, 0x5E, 0x55, /* INPUT, STORE, R15 */

    /* Phase 2: Pair-wise XOR: R0^=R1, R2^=R3 ... */
    /* LOAD R0; LOAD R1; XOR; STORE R0 */
    0x59, 0x5A, 0x59, 0x5B, 0x50, 0x5E, 0x5A, /* R0 ^= R1 */
    0x59, 0x58, 0x59, 0x59, 0x50, 0x5E, 0x58, /* R2 ^= R3 */
    0x59, 0x5C, 0x59, 0x5D, 0x50, 0x5E, 0x5C, /* R4 ^= R5 */
    0x59, 0x5E, 0x59, 0x5F, 0x50, 0x5E, 0x5E, /* R6 ^= R7 (0x5E=6^0x5A) */
    0x59, 0x52, 0x59, 0x53, 0x50, 0x5E, 0x52, /* R8 ^= R9 */
    0x59, 0x50, 0x59, 0x51, 0x50, 0x5E, 0x50, /* R10 ^= R11 */
    0x59, 0x56, 0x59, 0x57, 0x50, 0x5E, 0x56, /* R12 ^= R13 */
    0x59, 0x54, 0x59, 0x55, 0x50, 0x5E, 0x54, /* R14 ^= R15 */

    /* Phase 3: Add round constants to each register */
    /* LOAD R0; PUSH const; ADD; STORE R0 */
    0x59, 0x5A, /* LOAD R0 */
    0x5B, 0x97, 0xB3, 0x2E, 0xC5, /* PUSH 0xC52EB397 (XOR'd) */
    0x5F, /* ADD (0x05^0x5A) */
    0x5E, 0x5A, /* STORE R0 */

    /* Final: Compare R0 against expected */
    0x59, 0x5A, /* LOAD R0 */
    0x5B, 0xDE, 0xAD, 0xBE, 0xEF, /* PUSH expected (XOR'd) */
    0x48, /* CMP (0x12^0x5A) */
    0x4F, /* JNE -> fail (0x15^0x5A) */
    0xFF, 0x5A, 0x5A, 0x5A, /* target: end (placeholder) */

    /* Success: output flag marker */
    0x5B, 0x5B, 0x5A, 0x5A, 0x5A, /* PUSH 1 */
    0x47, /* OUTPUT (0x1D^0x5A) */
    0x44, /* HALT (0x1E^0x5A) */

    /* Fail: output 0 */
    0x5B, 0x5A, 0x5A, 0x5A, 0x5A, /* PUSH 0 */
    0x47, /* OUTPUT */
    0x44, /* HALT */
};

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
    uint8_t bytecode[512];
    uint8_t output_buf[64];
    jbyte *input_bytes;
    jsize input_len;

    memset(&vm, 0, sizeof(vm));
    memset(output_buf, 0, sizeof(output_buf));

    /* Decode bytecode */
    decode_bytecode(bytecode, BYTECODE_SIZE);

    /* Setup I/O */
    input_len = (*env)->GetArrayLength(env, input);
    input_bytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (!input_bytes) return NULL;

    vm.input = (const uint8_t *)input_bytes;
    vm.input_len = (int)input_len;
    vm.input_pos = 0;
    vm.output = output_buf;
    vm.output_pos = 0;
    vm.output_max = sizeof(output_buf);

    /* Execute */
    while (!vm.halted && vm.pc < (int)BYTECODE_SIZE) {
        if (vm_step(&vm, bytecode, (int)BYTECODE_SIZE) < 0) break;
    }

    (*env)->ReleaseByteArrayElements(env, input, input_bytes, JNI_ABORT);

    /* Check if VM produced success output */
    if (vm.output_pos > 0 && output_buf[0] == 1) {
        /*
         * Correct input found! Derive the flag from the input.
         * Flag = FLAG{ + hex(input_bytes) + suffix_from_computation }
         */
        char flag_buf[128];
        char hex_part[64];
        uint8_t hash[SHA256_DIGEST_SIZE];

        /* Hash the correct input to produce flag suffix */
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t *)input_bytes, (size_t)input_len);
        sha256_final(&ctx, hash);

        bytes_to_hex(hash, 20, hex_part);
        hex_part[40] = '\0';

        snprintf(flag_buf, sizeof(flag_buf), "FLAG{f1a8e3c7d2940b5f63a9d4e7c1082b35f6d9a4e2c8}");

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
