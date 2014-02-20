/*
 * Copyright (C) 2013 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define LOG_TAG "ArmToArm64Assembler"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cutils/log.h>
#include <cutils/properties.h>
#include <private/pixelflinger/ggl_context.h>

#include "codeflinger/Arm64Assembler.h"
#include "codeflinger/CodeCache.h"
#include "codeflinger/Arm64Disassembler.h"


/*
** --------------------------------------------
** Support for Arm64 in GGLAssembler JIT
** --------------------------------------------
**
** Approach
** - GGLAssembler and associated files are largely un-changed.
** - A translator class maps ArmAssemblerInterface calls to
**   generate Arm64 instructions.
**
** ----------------------
** ArmToArm64Assembler
** ----------------------
**
** - Subclassed from ArmAssemblerInterface
**
** - Translates each ArmAssemblerInterface call to generate
**   one or more Arm64 instructions  as necessary.
**
** - Does not implement ArmAssemblerInterface portions unused by GGLAssembler
**   It calls NOT_IMPLEMENTED() for such cases, which in turn logs
**    a fatal message.
**
** - Uses A64_.. series of functions to generate instruction machine code
**   for Arm64 instructions. These functions also log the instruction
**   to LOG, if ARM64_ASM_DEBUG define is set to 1
**
** - Dumps machine code and eqvt assembly if "debug.pf.disasm" option is set
**   It uses arm64_disassemble to perform disassembly
**
** - Uses register 13 (SP in ARM), 15 (PC in ARM), 16, 17 for storing
**   intermediate results. GGLAssembler does not use SP and PC as these
**   registers are marked as reserved. The temporary registers are not
**   saved/restored on stack as these are caller-saved registers in Arm64
**
** - Uses CSEL instruction to support conditional execution. The result is
**   stored in a temporary register and then copied to the target register
**   if the condition is true.
**
** - In the case of conditional data transfer instructions, conditional
**   branch is used to skip over instruction, if the condition is false
**
** - Wherever possible, immediate values are transferred to temporary
**   register prior to processing. This simplifies overall implementation
**   as instructions requiring immediate values are converted to
**   move immediate instructions followed by register-register instruction.
**
** --------------------------------------------
** ArmToArm64Assembler unit test bench
** --------------------------------------------
**
** - Tests ArmToArm64Assembler interface for all the possible
**   ways in which GGLAssembler uses ArmAssemblerInterface interface.
**
** - Uses test jacket (written in assembly) to set the registers,
**   condition flags prior to calling generated instruction. It also
**   copies registers and flags at the end of execution. Caller then
**   checks if generated code performed correct operation based on
**   output registers and flags.
**
** - Broadly contains three type of tests, (i) data operation tests
**   (ii) data transfer tests and (iii) LDM/STM tests.
**
** ----------------------
** Arm64 disassembler
** ----------------------
** - This disassembler disassembles only those machine codes which can be
**   generated by ArmToArm64Assembler. It has a unit testbench which
**   tests all the instructions supported by the disassembler.
**
** ------------------------------------------------------------------
** ARMAssembler/ARMAssemblerInterface/ARMAssemblerProxy changes
** ------------------------------------------------------------------
**
** - In existing code, addresses were being handled as 32 bit values at
**   certain places.
**
** - Added a new set of functions for address load/store/manipulation.
**   These are ADDR_LDR, ADDR_STR, ADDR_ADD, ADDR_SUB and they map to
**   default 32 bit implementations in ARMAssemblerInterface.
**
** - ArmToArm64Assembler maps these functions to appropriate 64 bit
**   functions.
**
** ----------------------
** GGLAssembler changes
** ----------------------
** - Since ArmToArm64Assembler can generate 4 Arm64 instructions for
**   each call in worst case, the memory required is set to 4 times
**   ARM memory
**
** - Address load/store/manipulation were changed to use new functions
**   added in the ARMAssemblerInterface.
**
*/


#define NOT_IMPLEMENTED()  LOG_FATAL("Arm instruction %s not yet implemented\n", __func__)

#define ARM64_ASM_DEBUG 0

#if ARM64_ASM_DEBUG
    #define LOG_INSTR(...) ALOGD("\t" __VA_ARGS__)
    #define LOG_LABEL(...) ALOGD(__VA_ARGS__)
#else
    #define LOG_INSTR(...) ((void)0)
    #define LOG_LABEL(...) ((void)0)
#endif

namespace android {

static const char* shift_codes[] =
{
    "LSL", "LSR", "ASR", "ROR"
};
static const char *cc_codes[] =
{
    "EQ", "NE", "CS", "CC", "MI",
    "PL", "VS", "VC", "HI", "LS",
    "GE", "LT", "GT", "LE", "AL", "NV"
};

ArmToArm64Assembler::ArmToArm64Assembler(const sp<Assembly>& assembly)
    :   ARMAssemblerInterface(),
        mAssembly(assembly)
{
    mBase = mPC = (uint32_t *)assembly->base();
    mDuration = ggl_system_time();
    mZeroReg = 13;
    mTmpReg1 = 15;
    mTmpReg2 = 16;
    mTmpReg3 = 17;
}

ArmToArm64Assembler::ArmToArm64Assembler(void *base)
    :   ARMAssemblerInterface(), mAssembly(NULL)
{
    mBase = mPC = (uint32_t *)base;
    mDuration = ggl_system_time();
    // Regs 13, 15, 16, 17 are used as temporary registers
    mZeroReg = 13;
    mTmpReg1 = 15;
    mTmpReg2 = 16;
    mTmpReg3 = 17;
}

ArmToArm64Assembler::~ArmToArm64Assembler()
{
}

uint32_t* ArmToArm64Assembler::pc() const
{
    return mPC;
}

uint32_t* ArmToArm64Assembler::base() const
{
    return mBase;
}

void ArmToArm64Assembler::reset()
{
    if(mAssembly == NULL)
        mPC = mBase;
    else
        mBase = mPC = (uint32_t *)mAssembly->base();
    mBranchTargets.clear();
    mLabels.clear();
    mLabelsInverseMapping.clear();
    mComments.clear();
#if ARM64_ASM_DEBUG
    ALOGI("RESET\n");
#endif
}

int ArmToArm64Assembler::getCodegenArch()
{
    return CODEGEN_ARCH_ARM64;
}

// ----------------------------------------------------------------------------

void ArmToArm64Assembler::disassemble(const char* name)
{
    if(name)
    {
        printf("%s:\n", name);
    }
    size_t count = pc()-base();
    uint32_t* i = base();
    while (count--)
    {
        ssize_t label = mLabelsInverseMapping.indexOfKey(i);
        if (label >= 0)
        {
            printf("%s:\n", mLabelsInverseMapping.valueAt(label));
        }
        ssize_t comment = mComments.indexOfKey(i);
        if (comment >= 0)
        {
            printf("; %s\n", mComments.valueAt(comment));
        }
        printf("%p:    %08x    ", i, uint32_t(i[0]));
        {
            char instr[256];
            ::arm64_disassemble(*i, instr);
            printf("%s\n", instr);
        }
        i++;
    }
}

void ArmToArm64Assembler::comment(const char* string)
{
    mComments.add(mPC, string);
    LOG_INSTR("//%s\n", string);
}

void ArmToArm64Assembler::label(const char* theLabel)
{
    mLabels.add(theLabel, mPC);
    mLabelsInverseMapping.add(mPC, theLabel);
    LOG_LABEL("%s:\n", theLabel);
}

void ArmToArm64Assembler::B(int cc, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    LOG_INSTR("B%s %s\n", cc_codes[cc], label );
    *mPC++ = (0x54 << 24) | cc;
}

void ArmToArm64Assembler::BL(int /*cc*/, const char* /*label*/)
{
    NOT_IMPLEMENTED(); //Not Required
}

// ----------------------------------------------------------------------------
//Prolog/Epilog & Generate...
// ----------------------------------------------------------------------------

void ArmToArm64Assembler::prolog()
{
    // write prolog code
    mPrologPC = mPC;
    *mPC++ = A64_MOVZ_X(mZeroReg,0,0);
}

void ArmToArm64Assembler::epilog(uint32_t /*touched*/)
{
    // write epilog code
    static const int XLR = 30;
    *mPC++ = A64_RET(XLR);
}

int ArmToArm64Assembler::generate(const char* name)
{
    // fixup all the branches
    size_t count = mBranchTargets.size();
    while (count--)
    {
        const branch_target_t& bt = mBranchTargets[count];
        uint32_t* target_pc = mLabels.valueFor(bt.label);
        LOG_ALWAYS_FATAL_IF(!target_pc,
                "error resolving branch targets, target_pc is null");
        int32_t offset = int32_t(target_pc - bt.pc);
        *bt.pc |= (offset & 0x7FFFF) << 5;
    }

    if(mAssembly != NULL)
        mAssembly->resize( int(pc()-base())*4 );

    // the instruction cache is flushed by CodeCache
    const int64_t duration = ggl_system_time() - mDuration;
    const char * const format = "generated %s (%d ins) at [%p:%p] in %ld ns\n";
    ALOGI(format, name, int(pc()-base()), base(), pc(), duration);


    char value[PROPERTY_VALUE_MAX];
    property_get("debug.pf.disasm", value, "0");
    if (atoi(value) != 0)
    {
        printf(format, name, int(pc()-base()), base(), pc(), duration);
        disassemble(name);
    }
    return NO_ERROR;
}

uint32_t* ArmToArm64Assembler::pcForLabel(const char* label)
{
    return mLabels.valueFor(label);
}

// ----------------------------------------------------------------------------
// Data Processing...
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::dataProcessingCommon(int opcode,
        int s, int Rd, int Rn, uint32_t Op2)
{
    if(opcode != opSUB && s == 1)
    {
        NOT_IMPLEMENTED(); //Not required
        return;
    }

    if(opcode != opSUB && opcode != opADD && opcode != opAND &&
       opcode != opORR && opcode != opMVN)
    {
        NOT_IMPLEMENTED(); //Not required
        return;
    }

    if(Op2 == OPERAND_REG_IMM && mAddrMode.reg_imm_shift > 31)
        {
        NOT_IMPLEMENTED();
        return;
    }

    //Store immediate in temporary register and convert
    //immediate operation into register operation
    if(Op2 == OPERAND_IMM)
    {
        int imm = mAddrMode.immediate;
        *mPC++ = A64_MOVZ_W(mTmpReg2, imm & 0x0000FFFF, 0);
        *mPC++ = A64_MOVK_W(mTmpReg2, (imm >> 16) & 0x0000FFFF, 16);
        Op2 = mTmpReg2;
    }


    {
        uint32_t shift;
        uint32_t amount;
        uint32_t Rm;

        if(Op2 == OPERAND_REG_IMM)
        {
            shift   = mAddrMode.reg_imm_type;
            amount  = mAddrMode.reg_imm_shift;
            Rm      = mAddrMode.reg_imm_Rm;
        }
        else if(Op2 < OPERAND_REG)
        {
            shift   = 0;
            amount  = 0;
            Rm      = Op2;
        }
        else
        {
            NOT_IMPLEMENTED(); //Not required
            return;
        }

        switch(opcode)
        {
            case opADD: *mPC++ = A64_ADD_W(Rd, Rn, Rm, shift, amount); break;
            case opAND: *mPC++ = A64_AND_W(Rd, Rn, Rm, shift, amount); break;
            case opORR: *mPC++ = A64_ORR_W(Rd, Rn, Rm, shift, amount); break;
            case opMVN: *mPC++ = A64_ORN_W(Rd, Rn, Rm, shift, amount); break;
            case opSUB: *mPC++ = A64_SUB_W(Rd, Rn, Rm, shift, amount, s);break;
        };

    }
}

void ArmToArm64Assembler::dataProcessing(int opcode, int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
    uint32_t Wd;

    if(cc != AL)
        Wd = mTmpReg1;
    else
        Wd = Rd;

    if(opcode == opADD || opcode == opAND || opcode == opORR ||opcode == opSUB)
    {
        dataProcessingCommon(opcode, s, Wd, Rn, Op2);
    }
    else if(opcode == opCMP)
    {
        dataProcessingCommon(opSUB, 1, mTmpReg3, Rn, Op2);
    }
    else if(opcode == opRSB)
    {
        dataProcessingCommon(opSUB, s, Wd, Rn, Op2);
        dataProcessingCommon(opSUB, s, Wd, mZeroReg, Wd);
    }
    else if(opcode == opMOV)
    {
        dataProcessingCommon(opORR, 0, Wd, mZeroReg, Op2);
        if(s == 1)
        {
            dataProcessingCommon(opSUB, 1, mTmpReg3, Wd, mZeroReg);
        }
    }
    else if(opcode == opMVN)
    {
        dataProcessingCommon(opMVN, s, Wd, mZeroReg, Op2);
    }
    else if(opcode == opBIC)
    {
        dataProcessingCommon(opMVN, s, mTmpReg3, mZeroReg, Op2);
        dataProcessingCommon(opAND, s, Wd, Rn, mTmpReg3);
    }
    else
    {
        NOT_IMPLEMENTED();
        return;
    }

    if(cc != AL)
    {
        *mPC++ = A64_CSEL_W(Rd, mTmpReg1, Rd, cc);
    }
}
// ----------------------------------------------------------------------------
// Address Processing...
// ----------------------------------------------------------------------------

void ArmToArm64Assembler::ADDR_ADD(int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required
    if(s  != 0) { NOT_IMPLEMENTED(); return;} //Not required


    if(Op2 == OPERAND_REG_IMM && mAddrMode.reg_imm_type == LSL)
    {
        int Rm = mAddrMode.reg_imm_Rm;
        int amount = mAddrMode.reg_imm_shift;
        *mPC++ = A64_ADD_X_Wm_SXTW(Rd, Rn, Rm, amount);
    }
    else if(Op2 < OPERAND_REG)
    {
        int Rm = Op2;
        int amount = 0;
        *mPC++ = A64_ADD_X_Wm_SXTW(Rd, Rn, Rm, amount);
    }
    else if(Op2 == OPERAND_IMM)
    {
        int imm = mAddrMode.immediate;
        *mPC++ = A64_MOVZ_W(mTmpReg1, imm & 0x0000FFFF, 0);
        *mPC++ = A64_MOVK_W(mTmpReg1, (imm >> 16) & 0x0000FFFF, 16);

        int Rm = mTmpReg1;
        int amount = 0;
        *mPC++ = A64_ADD_X_Wm_SXTW(Rd, Rn, Rm, amount);
    }
    else
    {
        NOT_IMPLEMENTED(); //Not required
    }
}

void ArmToArm64Assembler::ADDR_SUB(int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required
    if(s  != 0) { NOT_IMPLEMENTED(); return;} //Not required

    if(Op2 == OPERAND_REG_IMM && mAddrMode.reg_imm_type == LSR)
    {
        *mPC++ = A64_ADD_W(mTmpReg1, mZeroReg, mAddrMode.reg_imm_Rm,
                           LSR, mAddrMode.reg_imm_shift);
        *mPC++ = A64_SUB_X_Wm_SXTW(Rd, Rn, mTmpReg1, 0);
    }
    else
    {
        NOT_IMPLEMENTED(); //Not required
    }
}

// ----------------------------------------------------------------------------
// multiply...
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::MLA(int cc, int s,int Rd, int Rm, int Rs, int Rn)
{
    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required

    *mPC++ = A64_MADD_W(Rd, Rm, Rs, Rn);
    if(s == 1)
        dataProcessingCommon(opSUB, 1, mTmpReg1, Rd, mZeroReg);
}
void ArmToArm64Assembler::MUL(int cc, int s, int Rd, int Rm, int Rs)
{
    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required
    if(s  != 0) { NOT_IMPLEMENTED(); return;} //Not required
    *mPC++ = A64_MADD_W(Rd, Rm, Rs, mZeroReg);
}
void ArmToArm64Assembler::UMULL(int /*cc*/, int /*s*/,
        int /*RdLo*/, int /*RdHi*/, int /*Rm*/, int /*Rs*/)
{
    NOT_IMPLEMENTED(); //Not required
}
void ArmToArm64Assembler::UMUAL(int /*cc*/, int /*s*/,
        int /*RdLo*/, int /*RdHi*/, int /*Rm*/, int /*Rs*/)
{
    NOT_IMPLEMENTED(); //Not required
}
void ArmToArm64Assembler::SMULL(int /*cc*/, int /*s*/,
        int /*RdLo*/, int /*RdHi*/, int /*Rm*/, int /*Rs*/)
{
    NOT_IMPLEMENTED(); //Not required
}
void ArmToArm64Assembler::SMUAL(int /*cc*/, int /*s*/,
        int /*RdLo*/, int /*RdHi*/, int /*Rm*/, int /*Rs*/)
{
    NOT_IMPLEMENTED(); //Not required
}

// ----------------------------------------------------------------------------
// branches relative to PC...
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::B(int /*cc*/, uint32_t* /*pc*/){
    NOT_IMPLEMENTED(); //Not required
}

void ArmToArm64Assembler::BL(int /*cc*/, uint32_t* /*pc*/){
    NOT_IMPLEMENTED(); //Not required
}

void ArmToArm64Assembler::BX(int /*cc*/, int /*Rn*/){
    NOT_IMPLEMENTED(); //Not required
}

// ----------------------------------------------------------------------------
// data transfer...
// ----------------------------------------------------------------------------
enum dataTransferOp
{
    opLDR,opLDRB,opLDRH,opSTR,opSTRB,opSTRH
};

void ArmToArm64Assembler::dataTransfer(int op, int cc,
                            int Rd, int Rn, uint32_t op_type, uint32_t size)
{
    const int XSP = 31;
    if(Rn == SP)
        Rn = XSP;

    if(op_type == OPERAND_IMM)
    {
        int addrReg;
        int imm = mAddrMode.immediate;
        if(imm >= 0 && imm < (1<<12))
            *mPC++ = A64_ADD_IMM_X(mTmpReg1, mZeroReg, imm, 0);
        else if(imm < 0 && -imm < (1<<12))
            *mPC++ = A64_SUB_IMM_X(mTmpReg1, mZeroReg, -imm, 0);
        else
        {
            NOT_IMPLEMENTED();
            return;
        }

        addrReg = Rn;
        if(mAddrMode.preindex == true || mAddrMode.postindex == true)
        {
            *mPC++ = A64_ADD_X(mTmpReg2, addrReg, mTmpReg1);
            if(mAddrMode.preindex == true)
                addrReg = mTmpReg2;
        }

        if(cc != AL)
            *mPC++ = A64_B_COND(cc^1, 8);

        *mPC++ = A64_LDRSTR_Wm_SXTW_0(op, size, Rd, addrReg, mZeroReg);

        if(mAddrMode.writeback == true)
            *mPC++ = A64_CSEL_X(Rn, mTmpReg2, Rn, cc);
    }
    else if(op_type == OPERAND_REG_OFFSET)
    {
        if(cc != AL)
            *mPC++ = A64_B_COND(cc^1, 8);
        *mPC++ = A64_LDRSTR_Wm_SXTW_0(op, size, Rd, Rn, mAddrMode.reg_offset);

    }
    else if(op_type > OPERAND_UNSUPPORTED)
    {
        if(cc != AL)
            *mPC++ = A64_B_COND(cc^1, 8);
        *mPC++ = A64_LDRSTR_Wm_SXTW_0(op, size, Rd, Rn, mZeroReg);
    }
    else
    {
        NOT_IMPLEMENTED(); // Not required
    }
    return;

}
void ArmToArm64Assembler::ADDR_LDR(int cc, int Rd, int Rn, uint32_t op_type)
{
    return dataTransfer(opLDR, cc, Rd, Rn, op_type, 64);
}
void ArmToArm64Assembler::ADDR_STR(int cc, int Rd, int Rn, uint32_t op_type)
{
    return dataTransfer(opSTR, cc, Rd, Rn, op_type, 64);
}
void ArmToArm64Assembler::LDR(int cc, int Rd, int Rn, uint32_t op_type)
{
    return dataTransfer(opLDR, cc, Rd, Rn, op_type);
}
void ArmToArm64Assembler::LDRB(int cc, int Rd, int Rn, uint32_t op_type)
{
    return dataTransfer(opLDRB, cc, Rd, Rn, op_type);
}
void ArmToArm64Assembler::STR(int cc, int Rd, int Rn, uint32_t op_type)
{
    return dataTransfer(opSTR, cc, Rd, Rn, op_type);
}

void ArmToArm64Assembler::STRB(int cc, int Rd, int Rn, uint32_t op_type)
{
    return dataTransfer(opSTRB, cc, Rd, Rn, op_type);
}

void ArmToArm64Assembler::LDRH(int cc, int Rd, int Rn, uint32_t op_type)
{
    return dataTransfer(opLDRH, cc, Rd, Rn, op_type);
}
void ArmToArm64Assembler::LDRSB(int /*cc*/, int /*Rd*/, int /*Rn*/, uint32_t /*offset*/)
{
    NOT_IMPLEMENTED(); //Not required
}
void ArmToArm64Assembler::LDRSH(int /*cc*/, int /*Rd*/, int /*Rn*/, uint32_t /*offset*/)
{
    NOT_IMPLEMENTED(); //Not required
}

void ArmToArm64Assembler::STRH(int cc, int Rd, int Rn, uint32_t op_type)
{
    return dataTransfer(opSTRH, cc, Rd, Rn, op_type);
}

// ----------------------------------------------------------------------------
// block data transfer...
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::LDM(int cc, int dir,
        int Rn, int W, uint32_t reg_list)
{
    const int XSP = 31;
    if(cc != AL || dir != IA || W == 0 || Rn != SP)
    {
        NOT_IMPLEMENTED();
        return;
    }

    for(int i = 0; i < 32; ++i)
    {
        if((reg_list & (1 << i)))
        {
            int reg = i;
            int size = 16;
            *mPC++ = A64_LDR_IMM_PostIndex(reg, XSP, size);
        }
    }
}

void ArmToArm64Assembler::STM(int cc, int dir,
        int Rn, int W, uint32_t reg_list)
{
    const int XSP = 31;
    if(cc != AL || dir != DB || W == 0 || Rn != SP)
    {
        NOT_IMPLEMENTED();
        return;
    }

    for(int i = 31; i >= 0; --i)
    {
        if((reg_list & (1 << i)))
        {
            int size = -16;
            int reg  = i;
            *mPC++ = A64_STR_IMM_PreIndex(reg, XSP, size);
        }
    }
}

// ----------------------------------------------------------------------------
// special...
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::SWP(int /*cc*/, int /*Rn*/, int /*Rd*/, int /*Rm*/)
{
    NOT_IMPLEMENTED(); //Not required
}
void ArmToArm64Assembler::SWPB(int /*cc*/, int /*Rn*/, int /*Rd*/, int /*Rm*/)
{
    NOT_IMPLEMENTED(); //Not required
}
void ArmToArm64Assembler::SWI(int /*cc*/, uint32_t /*comment*/)
{
    NOT_IMPLEMENTED(); //Not required
}

// ----------------------------------------------------------------------------
// DSP instructions...
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::PLD(int /*Rn*/, uint32_t /*offset*/) {
    NOT_IMPLEMENTED(); //Not required
}

void ArmToArm64Assembler::CLZ(int /*cc*/, int /*Rd*/, int /*Rm*/)
{
    NOT_IMPLEMENTED(); //Not required
}

void ArmToArm64Assembler::QADD(int /*cc*/, int /*Rd*/, int /*Rm*/, int /*Rn*/)
{
    NOT_IMPLEMENTED(); //Not required
}

void ArmToArm64Assembler::QDADD(int /*cc*/, int /*Rd*/, int /*Rm*/, int /*Rn*/)
{
    NOT_IMPLEMENTED(); //Not required
}

void ArmToArm64Assembler::QSUB(int /*cc*/, int /*Rd*/, int /*Rm*/, int /*Rn*/)
{
    NOT_IMPLEMENTED(); //Not required
}

void ArmToArm64Assembler::QDSUB(int /*cc*/, int /*Rd*/, int /*Rm*/, int /*Rn*/)
{
    NOT_IMPLEMENTED(); //Not required
}

// ----------------------------------------------------------------------------
// 16 x 16 multiplication
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::SMUL(int cc, int xy,
                int Rd, int Rm, int Rs)
{
    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required

    if (xy & xyTB)
        *mPC++ = A64_SBFM_W(mTmpReg1, Rm, 16, 31);
    else
        *mPC++ = A64_SBFM_W(mTmpReg1, Rm, 0, 15);

    if (xy & xyBT)
        *mPC++ = A64_SBFM_W(mTmpReg2, Rs, 16, 31);
    else
        *mPC++ = A64_SBFM_W(mTmpReg2, Rs, 0, 15);

    *mPC++ = A64_MADD_W(Rd,mTmpReg1,mTmpReg2, mZeroReg);
}
// ----------------------------------------------------------------------------
// 32 x 16 multiplication
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::SMULW(int cc, int y, int Rd, int Rm, int Rs)
{
    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required

    if (y & yT)
        *mPC++ = A64_SBFM_W(mTmpReg1, Rs, 16, 31);
    else
        *mPC++ = A64_SBFM_W(mTmpReg1, Rs, 0, 15);

    *mPC++ = A64_SBFM_W(mTmpReg2, Rm, 0, 31);
    *mPC++ = A64_SMADDL(mTmpReg3,mTmpReg1,mTmpReg2, mZeroReg);
    *mPC++ = A64_UBFM_X(Rd,mTmpReg3, 16, 47);
}
// ----------------------------------------------------------------------------
// 16 x 16 multiplication and accumulate
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::SMLA(int cc, int xy, int Rd, int Rm, int Rs, int Rn)
{
    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required
    if(xy != xyBB) { NOT_IMPLEMENTED(); return;} //Not required

    *mPC++ = A64_SBFM_W(mTmpReg1, Rm, 0, 15);
    *mPC++ = A64_SBFM_W(mTmpReg2, Rs, 0, 15);
    *mPC++ = A64_MADD_W(Rd, mTmpReg1, mTmpReg2, Rn);
}

void ArmToArm64Assembler::SMLAL(int /*cc*/, int /*xy*/,
                int /*RdHi*/, int /*RdLo*/, int /*Rs*/, int /*Rm*/)
{
    NOT_IMPLEMENTED(); //Not required
    return;
}

void ArmToArm64Assembler::SMLAW(int /*cc*/, int /*y*/,
                int /*Rd*/, int /*Rm*/, int /*Rs*/, int /*Rn*/)
{
    NOT_IMPLEMENTED(); //Not required
    return;
}

// ----------------------------------------------------------------------------
// Byte/half word extract and extend
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::UXTB16(int cc, int Rd, int Rm, int rotate)
{
    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required

    *mPC++ = A64_EXTR_W(mTmpReg1, Rm, Rm, rotate * 8);

    uint32_t imm = 0x00FF00FF;
    *mPC++ = A64_MOVZ_W(mTmpReg2, imm & 0xFFFF, 0);
    *mPC++ = A64_MOVK_W(mTmpReg2, (imm >> 16) & 0x0000FFFF, 16);
    *mPC++ = A64_AND_W(Rd,mTmpReg1, mTmpReg2);
}

// ----------------------------------------------------------------------------
// Bit manipulation
// ----------------------------------------------------------------------------
void ArmToArm64Assembler::UBFX(int cc, int Rd, int Rn, int lsb, int width)
{
    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required
    *mPC++ = A64_UBFM_W(Rd, Rn, lsb, lsb + width - 1);
}
// ----------------------------------------------------------------------------
// Shifters...
// ----------------------------------------------------------------------------
int ArmToArm64Assembler::buildImmediate(
        uint32_t immediate, uint32_t& rot, uint32_t& imm)
{
    rot = 0;
    imm = immediate;
    return 0; // Always true
}


bool ArmToArm64Assembler::isValidImmediate(uint32_t immediate)
{
    uint32_t rot, imm;
    return buildImmediate(immediate, rot, imm) == 0;
}

uint32_t ArmToArm64Assembler::imm(uint32_t immediate)
{
    mAddrMode.immediate = immediate;
    mAddrMode.writeback = false;
    mAddrMode.preindex  = false;
    mAddrMode.postindex = false;
    return OPERAND_IMM;

}

uint32_t ArmToArm64Assembler::reg_imm(int Rm, int type, uint32_t shift)
{
    mAddrMode.reg_imm_Rm = Rm;
    mAddrMode.reg_imm_type = type;
    mAddrMode.reg_imm_shift = shift;
    return OPERAND_REG_IMM;
}

uint32_t ArmToArm64Assembler::reg_rrx(int /*Rm*/)
{
    NOT_IMPLEMENTED();
    return OPERAND_UNSUPPORTED;
}

uint32_t ArmToArm64Assembler::reg_reg(int /*Rm*/, int /*type*/, int /*Rs*/)
{
    NOT_IMPLEMENTED(); //Not required
    return OPERAND_UNSUPPORTED;
}
// ----------------------------------------------------------------------------
// Addressing modes...
// ----------------------------------------------------------------------------
uint32_t ArmToArm64Assembler::immed12_pre(int32_t immed12, int W)
{
    mAddrMode.immediate = immed12;
    mAddrMode.writeback = W;
    mAddrMode.preindex  = true;
    mAddrMode.postindex = false;
    return OPERAND_IMM;
}

uint32_t ArmToArm64Assembler::immed12_post(int32_t immed12)
{
    mAddrMode.immediate = immed12;
    mAddrMode.writeback = true;
    mAddrMode.preindex  = false;
    mAddrMode.postindex = true;
    return OPERAND_IMM;
}

uint32_t ArmToArm64Assembler::reg_scale_pre(int Rm, int type,
        uint32_t shift, int W)
{
    if(type != 0 || shift != 0 || W != 0)
    {
        NOT_IMPLEMENTED(); //Not required
        return OPERAND_UNSUPPORTED;
    }
    else
    {
        mAddrMode.reg_offset = Rm;
        return OPERAND_REG_OFFSET;
    }
}

uint32_t ArmToArm64Assembler::reg_scale_post(int /*Rm*/, int /*type*/, uint32_t /*shift*/)
{
    NOT_IMPLEMENTED(); //Not required
    return OPERAND_UNSUPPORTED;
}

uint32_t ArmToArm64Assembler::immed8_pre(int32_t immed8, int W)
{
    mAddrMode.immediate = immed8;
    mAddrMode.writeback = W;
    mAddrMode.preindex  = true;
    mAddrMode.postindex = false;
    return OPERAND_IMM;
}

uint32_t ArmToArm64Assembler::immed8_post(int32_t immed8)
{
    mAddrMode.immediate = immed8;
    mAddrMode.writeback = true;
    mAddrMode.preindex  = false;
    mAddrMode.postindex = true;
    return OPERAND_IMM;
}

uint32_t ArmToArm64Assembler::reg_pre(int Rm, int W)
{
    if(W != 0)
    {
        NOT_IMPLEMENTED(); //Not required
        return OPERAND_UNSUPPORTED;
    }
    else
    {
        mAddrMode.reg_offset = Rm;
        return OPERAND_REG_OFFSET;
    }
}

uint32_t ArmToArm64Assembler::reg_post(int /*Rm*/)
{
    NOT_IMPLEMENTED(); //Not required
    return OPERAND_UNSUPPORTED;
}

// ----------------------------------------------------------------------------
// A64 instructions
// ----------------------------------------------------------------------------

static const char * dataTransferOpName[] =
{
    "LDR","LDRB","LDRH","STR","STRB","STRH"
};

static const uint32_t dataTransferOpCode [] =
{
    ((0xB8u << 24) | (0x3 << 21) | (0x6 << 13) | (0x0 << 12) |(0x1 << 11)),
    ((0x38u << 24) | (0x3 << 21) | (0x6 << 13) | (0x1 << 12) |(0x1 << 11)),
    ((0x78u << 24) | (0x3 << 21) | (0x6 << 13) | (0x0 << 12) |(0x1 << 11)),
    ((0xB8u << 24) | (0x1 << 21) | (0x6 << 13) | (0x0 << 12) |(0x1 << 11)),
    ((0x38u << 24) | (0x1 << 21) | (0x6 << 13) | (0x1 << 12) |(0x1 << 11)),
    ((0x78u << 24) | (0x1 << 21) | (0x6 << 13) | (0x0 << 12) |(0x1 << 11))
};
uint32_t ArmToArm64Assembler::A64_LDRSTR_Wm_SXTW_0(uint32_t op,
                            uint32_t size, uint32_t Rt,
                            uint32_t Rn, uint32_t Rm)
{
    if(size == 32)
    {
        LOG_INSTR("%s W%d, [X%d, W%d, SXTW #0]\n",
                   dataTransferOpName[op], Rt, Rn, Rm);
        return(dataTransferOpCode[op] | (Rm << 16) | (Rn << 5) | Rt);
    }
    else
    {
        LOG_INSTR("%s X%d, [X%d, W%d, SXTW #0]\n",
                  dataTransferOpName[op], Rt, Rn, Rm);
        return(dataTransferOpCode[op] | (0x1<<30) | (Rm<<16) | (Rn<<5)|Rt);
    }
}

uint32_t ArmToArm64Assembler::A64_STR_IMM_PreIndex(uint32_t Rt,
                            uint32_t Rn, int32_t simm)
{
    if(Rn == 31)
        LOG_INSTR("STR W%d, [SP, #%d]!\n", Rt, simm);
    else
        LOG_INSTR("STR W%d, [X%d, #%d]!\n", Rt, Rn, simm);

    uint32_t imm9 = (unsigned)(simm) & 0x01FF;
    return (0xB8 << 24) | (imm9 << 12) | (0x3 << 10) | (Rn << 5) | Rt;
}

uint32_t ArmToArm64Assembler::A64_LDR_IMM_PostIndex(uint32_t Rt,
                            uint32_t Rn, int32_t simm)
{
    if(Rn == 31)
        LOG_INSTR("LDR W%d, [SP], #%d\n",Rt,simm);
    else
        LOG_INSTR("LDR W%d, [X%d], #%d\n",Rt, Rn, simm);

    uint32_t imm9 = (unsigned)(simm) & 0x01FF;
    return (0xB8 << 24) | (0x1 << 22) |
             (imm9 << 12) | (0x1 << 10) | (Rn << 5) | Rt;

}
uint32_t ArmToArm64Assembler::A64_ADD_X_Wm_SXTW(uint32_t Rd,
                               uint32_t Rn,
                               uint32_t Rm,
                               uint32_t amount)
{
    LOG_INSTR("ADD X%d, X%d, W%d, SXTW #%d\n", Rd, Rn, Rm, amount);
    return ((0x8B << 24) | (0x1 << 21) |(Rm << 16) |
              (0x6 << 13) | (amount << 10) | (Rn << 5) | Rd);

}

uint32_t ArmToArm64Assembler::A64_SUB_X_Wm_SXTW(uint32_t Rd,
                               uint32_t Rn,
                               uint32_t Rm,
                               uint32_t amount)
{
    LOG_INSTR("SUB X%d, X%d, W%d, SXTW #%d\n", Rd, Rn, Rm, amount);
    return ((0xCB << 24) | (0x1 << 21) |(Rm << 16) |
            (0x6 << 13) | (amount << 10) | (Rn << 5) | Rd);

}

uint32_t ArmToArm64Assembler::A64_B_COND(uint32_t cc, uint32_t offset)
{
    LOG_INSTR("B.%s #.+%d\n", cc_codes[cc], offset);
    return (0x54 << 24) | ((offset/4) << 5) | (cc);

}
uint32_t ArmToArm64Assembler::A64_ADD_X(uint32_t Rd, uint32_t Rn,
                                          uint32_t Rm, uint32_t shift,
                                          uint32_t amount)
{
    LOG_INSTR("ADD X%d, X%d, X%d, %s #%d\n",
               Rd, Rn, Rm, shift_codes[shift], amount);
    return ((0x8B << 24) | (shift << 22) | ( Rm << 16) |
            (amount << 10) |(Rn << 5) | Rd);
}
uint32_t ArmToArm64Assembler::A64_ADD_IMM_X(uint32_t Rd, uint32_t Rn,
                                          uint32_t imm, uint32_t shift)
{
    LOG_INSTR("ADD X%d, X%d, #%d, LSL #%d\n", Rd, Rn, imm, shift);
    return (0x91 << 24) | ((shift/12) << 22) | (imm << 10) | (Rn << 5) | Rd;
}

uint32_t ArmToArm64Assembler::A64_SUB_IMM_X(uint32_t Rd, uint32_t Rn,
                                          uint32_t imm, uint32_t shift)
{
    LOG_INSTR("SUB X%d, X%d, #%d, LSL #%d\n", Rd, Rn, imm, shift);
    return (0xD1 << 24) | ((shift/12) << 22) | (imm << 10) | (Rn << 5) | Rd;
}

uint32_t ArmToArm64Assembler::A64_ADD_W(uint32_t Rd, uint32_t Rn,
                                          uint32_t Rm, uint32_t shift,
                                          uint32_t amount)
{
    LOG_INSTR("ADD W%d, W%d, W%d, %s #%d\n",
               Rd, Rn, Rm, shift_codes[shift], amount);
    return ((0x0B << 24) | (shift << 22) | ( Rm << 16) |
            (amount << 10) |(Rn << 5) | Rd);
}

uint32_t ArmToArm64Assembler::A64_SUB_W(uint32_t Rd, uint32_t Rn,
                                          uint32_t Rm, uint32_t shift,
                                          uint32_t amount,
                                          uint32_t setflag)
{
    if(setflag == 0)
    {
        LOG_INSTR("SUB W%d, W%d, W%d, %s #%d\n",
               Rd, Rn, Rm, shift_codes[shift], amount);
        return ((0x4B << 24) | (shift << 22) | ( Rm << 16) |
                (amount << 10) |(Rn << 5) | Rd);
    }
    else
    {
        LOG_INSTR("SUBS W%d, W%d, W%d, %s #%d\n",
                   Rd, Rn, Rm, shift_codes[shift], amount);
        return ((0x6B << 24) | (shift << 22) | ( Rm << 16) |
                (amount << 10) |(Rn << 5) | Rd);
    }
}

uint32_t ArmToArm64Assembler::A64_AND_W(uint32_t Rd, uint32_t Rn,
                                          uint32_t Rm, uint32_t shift,
                                          uint32_t amount)
{
    LOG_INSTR("AND W%d, W%d, W%d, %s #%d\n",
               Rd, Rn, Rm, shift_codes[shift], amount);
    return ((0x0A << 24) | (shift << 22) | ( Rm << 16) |
            (amount << 10) |(Rn << 5) | Rd);
}

uint32_t ArmToArm64Assembler::A64_ORR_W(uint32_t Rd, uint32_t Rn,
                                          uint32_t Rm, uint32_t shift,
                                          uint32_t amount)
{
    LOG_INSTR("ORR W%d, W%d, W%d, %s #%d\n",
               Rd, Rn, Rm, shift_codes[shift], amount);
    return ((0x2A << 24) | (shift << 22) | ( Rm << 16) |
            (amount << 10) |(Rn << 5) | Rd);
}

uint32_t ArmToArm64Assembler::A64_ORN_W(uint32_t Rd, uint32_t Rn,
                                          uint32_t Rm, uint32_t shift,
                                          uint32_t amount)
{
    LOG_INSTR("ORN W%d, W%d, W%d, %s #%d\n",
               Rd, Rn, Rm, shift_codes[shift], amount);
    return ((0x2A << 24) | (shift << 22) | (0x1 << 21) | ( Rm << 16) |
            (amount << 10) |(Rn << 5) | Rd);
}

uint32_t ArmToArm64Assembler::A64_CSEL_X(uint32_t Rd, uint32_t Rn,
                                           uint32_t Rm, uint32_t cond)
{
    LOG_INSTR("CSEL X%d, X%d, X%d, %s\n", Rd, Rn, Rm, cc_codes[cond]);
    return ((0x9A << 24)|(0x1 << 23)|(Rm << 16) |(cond << 12)| (Rn << 5) | Rd);
}

uint32_t ArmToArm64Assembler::A64_CSEL_W(uint32_t Rd, uint32_t Rn,
                                           uint32_t Rm, uint32_t cond)
{
    LOG_INSTR("CSEL W%d, W%d, W%d, %s\n", Rd, Rn, Rm, cc_codes[cond]);
    return ((0x1A << 24)|(0x1 << 23)|(Rm << 16) |(cond << 12)| (Rn << 5) | Rd);
}

uint32_t ArmToArm64Assembler::A64_RET(uint32_t Rn)
{
    LOG_INSTR("RET X%d\n", Rn);
    return ((0xD6 << 24) | (0x1 << 22) | (0x1F << 16) | (Rn << 5));
}

uint32_t ArmToArm64Assembler::A64_MOVZ_X(uint32_t Rd, uint32_t imm,
                                         uint32_t shift)
{
    LOG_INSTR("MOVZ X%d, #0x%x, LSL #%d\n", Rd, imm, shift);
    return(0xD2 << 24) | (0x1 << 23) | ((shift/16) << 21) |  (imm << 5) | Rd;
}

uint32_t ArmToArm64Assembler::A64_MOVK_W(uint32_t Rd, uint32_t imm,
                                         uint32_t shift)
{
    LOG_INSTR("MOVK W%d, #0x%x, LSL #%d\n", Rd, imm, shift);
    return (0x72 << 24) | (0x1 << 23) | ((shift/16) << 21) | (imm << 5) | Rd;
}

uint32_t ArmToArm64Assembler::A64_MOVZ_W(uint32_t Rd, uint32_t imm,
                                         uint32_t shift)
{
    LOG_INSTR("MOVZ W%d, #0x%x, LSL #%d\n", Rd, imm, shift);
    return(0x52 << 24) | (0x1 << 23) | ((shift/16) << 21) |  (imm << 5) | Rd;
}

uint32_t ArmToArm64Assembler::A64_SMADDL(uint32_t Rd, uint32_t Rn,
                                           uint32_t Rm, uint32_t Ra)
{
    LOG_INSTR("SMADDL X%d, W%d, W%d, X%d\n",Rd, Rn, Rm, Ra);
    return ((0x9B << 24) | (0x1 << 21) | (Rm << 16)|(Ra << 10)|(Rn << 5) | Rd);
}

uint32_t ArmToArm64Assembler::A64_MADD_W(uint32_t Rd, uint32_t Rn,
                                           uint32_t Rm, uint32_t Ra)
{
    LOG_INSTR("MADD W%d, W%d, W%d, W%d\n",Rd, Rn, Rm, Ra);
    return ((0x1B << 24) | (Rm << 16) | (Ra << 10) |(Rn << 5) | Rd);
}

uint32_t ArmToArm64Assembler::A64_SBFM_W(uint32_t Rd, uint32_t Rn,
                                           uint32_t immr, uint32_t imms)
{
    LOG_INSTR("SBFM W%d, W%d, #%d, #%d\n", Rd, Rn, immr, imms);
    return ((0x13 << 24) | (immr << 16) | (imms << 10) | (Rn << 5) | Rd);

}
uint32_t ArmToArm64Assembler::A64_UBFM_W(uint32_t Rd, uint32_t Rn,
                                           uint32_t immr, uint32_t imms)
{
    LOG_INSTR("UBFM W%d, W%d, #%d, #%d\n", Rd, Rn, immr, imms);
    return ((0x53 << 24) | (immr << 16) | (imms << 10) | (Rn << 5) | Rd);

}
uint32_t ArmToArm64Assembler::A64_UBFM_X(uint32_t Rd, uint32_t Rn,
                                           uint32_t immr, uint32_t imms)
{
    LOG_INSTR("UBFM X%d, X%d, #%d, #%d\n", Rd, Rn, immr, imms);
    return ((0xD3 << 24) | (0x1 << 22) |
            (immr << 16) | (imms << 10) | (Rn << 5) | Rd);

}
uint32_t ArmToArm64Assembler::A64_EXTR_W(uint32_t Rd, uint32_t Rn,
                                           uint32_t Rm, uint32_t lsb)
{
    LOG_INSTR("EXTR W%d, W%d, W%d, #%d\n", Rd, Rn, Rm, lsb);
    return (0x13 << 24)|(0x1 << 23) | (Rm << 16) | (lsb << 10)|(Rn << 5) | Rd;
}

}; // namespace android

