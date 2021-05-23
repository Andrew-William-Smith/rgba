use crate::decode_succeeds;
use rgba::cpu::{instruction::*, RegisterNumber};

/// Shorthand for defining a register number, since we use them **everywhere**.
const fn r(number: u8) -> RegisterNumber {
    RegisterNumber(number)
}

/// Assert that the condition of each decoded instructions matches the expected
/// condition.
macro_rules! conditions_match {
    ($($bytecode:literal => $condition:ident),+$(,)?) => {
        $(
            match Instruction::decode($bytecode) {
                Some(Instruction::Branch(Branch { condition: c, .. })) => assert_eq!(c, Condition::$condition),
                _ => panic!("Instruction decoding failed!"),
            }
        )+
    }
}

#[test]
fn condition_opcodes() {
    conditions_match!(
        0x0A000000 => Equal,
        0x1A000000 => NotEqual,
        0x2A000000 => HigherOrSame,
        0x3A000000 => Lower,
        0x4A000000 => Negative,
        0x5A000000 => NonNegative,
        0x6A000000 => Overflow,
        0x7A000000 => NoOverflow,
        0x8A000000 => Higher,
        0x9A000000 => LowerOrSame,
        0xAA000000 => GreaterOrEqual,
        0xBA000000 => Less,
        0xCA000000 => Greater,
        0xDA000000 => LessOrEqual,
        0xEA000000 => Always,
    );
}

#[test]
fn block_data_transfer() {
    use BlockTransferMode::*;

    decode_succeeds!(
        BlockDataTransfer,
        // Mnemonics for stack operations with each addressing mode.
        0xE9BDE00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0xE00F } => "ldmed sp!,{r0-r3,sp-pc}",
        0xE8BDE00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0xE00F } => "ldmfd sp!,{r0-r3,sp-pc}",
        0xE93DE00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: true, base: r(13) }, registers: 0xE00F } => "ldmea sp!,{r0-r3,sp-pc}",
        0xE83DE00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: true, base: r(13) }, registers: 0xE00F } => "ldmfa sp!,{r0-r3,sp-pc}",
        0xE9ADE00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: false, base: r(13) }, registers: 0xE00F } => "stmfa sp!,{r0-r3,sp-pc}",
        0xE8ADE00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: false, base: r(13) }, registers: 0xE00F } => "stmea sp!,{r0-r3,sp-pc}",
        0xE92DE00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: false, base: r(13) }, registers: 0xE00F } => "stmfd sp!,{r0-r3,sp-pc}",
        0xE82DE00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: false, base: r(13) }, registers: 0xE00F } => "stmed sp!,{r0-r3,sp-pc}",
        // Mnemonics for non-stack operations.
        0xE9B7E00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(7) }, registers: 0xE00F } => "ldmib r7!,{r0-r3,sp-pc}",
        0xE8B7E00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: true, base: r(7) }, registers: 0xE00F } => "ldmia r7!,{r0-r3,sp-pc}",
        0xE937E00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: true, base: r(7) }, registers: 0xE00F } => "ldmdb r7!,{r0-r3,sp-pc}",
        0xE837E00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: true, base: r(7) }, registers: 0xE00F } => "ldmda r7!,{r0-r3,sp-pc}",
        0xE9A7E00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: false, base: r(7) }, registers: 0xE00F } => "stmib r7!,{r0-r3,sp-pc}",
        0xE8A7E00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: false, base: r(7) }, registers: 0xE00F } => "stmia r7!,{r0-r3,sp-pc}",
        0xE927E00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: false, base: r(7) }, registers: 0xE00F } => "stmdb r7!,{r0-r3,sp-pc}",
        0xE827E00F => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: false, base: r(7) }, registers: 0xE00F } => "stmda r7!,{r0-r3,sp-pc}",
        // Alternate banking modes.
        0xE9D08000 => BlockDataTransfer { condition: Always, mode: LoadSpsr, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(0) }, registers: 0x8000 } => "ldmib r0,{pc}^",
        0xE9C08000 => BlockDataTransfer { condition: Always, mode: UserBank, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(0) }, registers: 0x8000 } => "stmib r0,{pc}^",
        0xE9D00008 => BlockDataTransfer { condition: Always, mode: UserBank, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(0) }, registers: 0x0008 } => "ldmib r0,{r3}^",
        0xE9C00008 => BlockDataTransfer { condition: Always, mode: UserBank, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(0) }, registers: 0x0008 } => "stmib r0,{r3}^",
        // Register formatting in disassembly.
        0x59BD5555 => BlockDataTransfer { condition: NonNegative, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0x5555 } => "ldmpled sp!,{r0,r2,r4,r6,r8,r10,r12,lr}",
        0x99BDAAAA => BlockDataTransfer { condition: LowerOrSame, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0xAAAA } => "ldmlsed sp!,{r1,r3,r5,r7,r9,r11,sp,pc}",
        0xE9BD7777 => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0x7777 } => "ldmed sp!,{r0-r2,r4-r6,r8-r10,r12-lr}",
    );
}

#[test]
fn branches() {
    decode_succeeds!(
        Branch,
        // Branch without link, forward and backward offsets.
        0xEA000000 => Branch { condition: Always, link: false, offset: 0 } => "b #+0",
        0x1A000000 => Branch { condition: NotEqual, link: false, offset: 0 } => "bne #+0",
        0xEA00CAFE => Branch { condition: Always, link: false, offset: 207_864 } => "b #+207864",
        0x6AF0000F => Branch { condition: Overflow, link: false, offset: -4_194_244 } => "bvs #-4194244",
        // Branch with link.
        0xEB000000 => Branch { condition: Always, link: true, offset: 0 } => "bl #+0",
        0x0B00BEEF => Branch { condition: Equal, link: true, offset: 195_516 } => "bleq #+195516",
        0x3B808080 => Branch { condition: Lower, link: true, offset: -33_422_848 } => "blcc #-33422848",
    );
}

#[test]
fn branch_and_exchange() {
    decode_succeeds!(
        BranchAndExchange,
        0xE12FFF10 => BranchAndExchange { condition: Always, source: r(0) } => "bx r0",
        0x212FFF17 => BranchAndExchange { condition: HigherOrSame, source: r(7) } => "bxcs r7",
        0xD12FFF1A => BranchAndExchange { condition: LessOrEqual, source: r(10) } => "bxle r10",
    );
}

#[test]
fn data_processing() {
    // Include some enums so these lines don't get too long.
    use ArithmeticOperation::*;
    use DataOperand::*;
    use ShiftType::*;

    fn simple_instruction(operation: ArithmeticOperation, set_cpsr: bool) -> DataProcessing {
        DataProcessing {
            condition: Condition::Always,
            operation,
            set_cpsr,
            operand1: r(1),
            destination: r(0),
            operand2: ShiftImmediate(LogicalShiftLeft, 0, r(2)),
        }
    }

    fn simple_data(operand2: DataOperand) -> DataProcessing {
        DataProcessing {
            condition: Condition::Always,
            operation: Add,
            set_cpsr: false,
            operand1: r(1),
            destination: r(0),
            operand2,
        }
    }

    decode_succeeds!(
        DataProcessing,
        // Simple opcodes without the CPSR flag explicitly set.
        0xE0010002 => simple_instruction(And, false) => "and r0,r1,r2",
        0xE0210002 => simple_instruction(ExclusiveOr, false) => "eor r0,r1,r2",
        0xE0410002 => simple_instruction(Subtract, false) => "sub r0,r1,r2",
        0xE0610002 => simple_instruction(ReverseSubtract, false) => "rsb r0,r1,r2",
        0xE0810002 => simple_instruction(Add, false) => "add r0,r1,r2",
        0xE0A10002 => simple_instruction(AddWithCarry, false) => "adc r0,r1,r2",
        0xE0C10002 => simple_instruction(SubtractWithCarry, false) => "sbc r0,r1,r2",
        0xE0E10002 => simple_instruction(ReverseSubtractWithCarry, false) => "rsc r0,r1,r2",
        0xE1010002 => simple_instruction(Test, false) => "tst r1,r2",
        0xE1210002 => simple_instruction(TestEqual, false) => "teq r1,r2",
        0xE1410002 => simple_instruction(CompareSubtract, false) => "cmp r1,r2",
        0xE1610002 => simple_instruction(CompareAdd, false) => "cmn r1,r2",
        0xE1810002 => simple_instruction(InclusiveOr, false) => "orr r0,r1,r2",
        0xE1A10002 => simple_instruction(Move, false) => "mov r0,r2",
        0xE1C10002 => simple_instruction(BitClear, false) => "bic r0,r1,r2",
        0xE1E10002 => simple_instruction(MoveInverse, false) => "mvn r0,r2",
        // Simple opcodes with the CPSR flag set; comparisons should not change.
        0xE0110002 => simple_instruction(And, true) => "ands r0,r1,r2",
        0xE0310002 => simple_instruction(ExclusiveOr, true) => "eors r0,r1,r2",
        0xE0510002 => simple_instruction(Subtract, true) => "subs r0,r1,r2",
        0xE0710002 => simple_instruction(ReverseSubtract, true) => "rsbs r0,r1,r2",
        0xE0910002 => simple_instruction(Add, true) => "adds r0,r1,r2",
        0xE0B10002 => simple_instruction(AddWithCarry, true) => "adcs r0,r1,r2",
        0xE0D10002 => simple_instruction(SubtractWithCarry, true) => "sbcs r0,r1,r2",
        0xE0F10002 => simple_instruction(ReverseSubtractWithCarry, true) => "rscs r0,r1,r2",
        0xE1110002 => simple_instruction(Test, true) => "tst r1,r2",
        0xE1310002 => simple_instruction(TestEqual, true) => "teq r1,r2",
        0xE1510002 => simple_instruction(CompareSubtract, true) => "cmp r1,r2",
        0xE1710002 => simple_instruction(CompareAdd, true) => "cmn r1,r2",
        0xE1910002 => simple_instruction(InclusiveOr, true) => "orrs r0,r1,r2",
        0xE1B10002 => simple_instruction(Move, true) => "movs r0,r2",
        0xE1D10002 => simple_instruction(BitClear, true) => "bics r0,r1,r2",
        0xE1F10002 => simple_instruction(MoveInverse, true) => "mvns r0,r2",
        // Immediate operand.
        0xE2810C0F => simple_data(Immediate(0xF00)) => "add r0,r1,#0xF00",
        // Shift operand 2 by an immediate value.
        0xE0810382 => simple_data(ShiftImmediate(LogicalShiftLeft, 7, r(2))) => "add r0,r1,r2,lsl #7",
        0xE08103A2 => simple_data(ShiftImmediate(LogicalShiftRight, 7, r(2))) => "add r0,r1,r2,lsr #7",
        0xE08103C2 => simple_data(ShiftImmediate(ArithmeticShiftRight, 7, r(2))) => "add r0,r1,r2,asr #7",
        0xE08103E2 => simple_data(ShiftImmediate(RotateRight, 7, r(2))) => "add r0,r1,r2,ror #7",
        0xE0810062 => simple_data(ShiftImmediate(RotateRight, 0, r(2))) => "add r0,r1,r2,rrx",
        // Shift operand 2 by a register value.
        0xE0810312 => simple_data(ShiftRegister(LogicalShiftLeft, r(3), r(2))) => "add r0,r1,r2,lsl r3",
        0xE0810332 => simple_data(ShiftRegister(LogicalShiftRight, r(3), r(2))) => "add r0,r1,r2,lsr r3",
        0xE0810352 => simple_data(ShiftRegister(ArithmeticShiftRight, r(3), r(2))) => "add r0,r1,r2,asr r3",
        0xE0810372 => simple_data(ShiftRegister(RotateRight, r(3), r(2))) => "add r0,r1,r2,ror r3",
        // Using R0 as a ROR operand should not disassemble as RRX.
        0xE0810072 => simple_data(ShiftRegister(RotateRight, r(0), r(2))) => "add r0,r1,r2,ror r0",
    );
}

#[test]
fn multiply() {
    decode_succeeds!(
        Multiply,
        // Permutations of accumulate and condition code control bits.
        0xE0000192 => Multiply { condition: Always, accumulate: false, set_cpsr: false, destination: r(0), addend: r(0), multiplicand1: r(1), multiplicand2: r(2) } => "mul r0,r2,r1",
        0xE0100192 => Multiply { condition: Always, accumulate: false, set_cpsr: true, destination: r(0), addend: r(0), multiplicand1: r(1), multiplicand2: r(2) } => "muls r0,r2,r1",
        0xE0201293 => Multiply { condition: Always, accumulate: true, set_cpsr: false, destination: r(0), addend: r(1), multiplicand1: r(2), multiplicand2: r(3) } => "mla r0,r3,r2,r1",
        0xE0301293 => Multiply { condition: Always, accumulate: true, set_cpsr: true, destination: r(0), addend: r(1), multiplicand1: r(2), multiplicand2: r(3) } => "mlas r0,r3,r2,r1",
        // With some different condition codes.
        0x00314392 => Multiply { condition: Equal, accumulate: true, set_cpsr: true, destination: r(1), addend: r(4), multiplicand1: r(3), multiplicand2: r(2) } => "mlaeqs r1,r2,r3,r4",
        0xA0130192 => Multiply { condition: GreaterOrEqual, accumulate: false, set_cpsr: true, destination: r(3), addend: r(0), multiplicand1: r(1), multiplicand2: r(2) } => "mulges r3,r2,r1",
    );
}

#[test]
fn multiply_long() {
    decode_succeeds!(
        MultiplyLong,
        // Permutations of all control bits.
        0xE0801392 => MultiplyLong { condition: Always, signed: false, accumulate: false, set_cpsr: false, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) } => "umull r1,r0,r2,r3",
        0xE0C01392 => MultiplyLong { condition: Always, signed: true, accumulate: false, set_cpsr: false, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) } => "smull r1,r0,r2,r3",
        0xE0A01392 => MultiplyLong { condition: Always, signed: false, accumulate: true, set_cpsr: false, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) } => "umlal r1,r0,r2,r3",
        0xE0E01392 => MultiplyLong { condition: Always, signed: true, accumulate: true, set_cpsr: false, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) } => "smlal r1,r0,r2,r3",
        0xE0901392 => MultiplyLong { condition: Always, signed: false, accumulate: false, set_cpsr: true, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) } => "umulls r1,r0,r2,r3",
        0xE0D01392 => MultiplyLong { condition: Always, signed: true, accumulate: false, set_cpsr: true, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) } => "smulls r1,r0,r2,r3",
        0xE0B01392 => MultiplyLong { condition: Always, signed: false, accumulate: true, set_cpsr: true, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) } => "umlals r1,r0,r2,r3",
        0xE0F01392 => MultiplyLong { condition: Always, signed: true, accumulate: true, set_cpsr: true, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) } => "smlals r1,r0,r2,r3",
        // With a different condition code, since these mnemonics are becoming alarmingly long.
        0x00F9A190 => MultiplyLong { condition: Equal, signed: true, accumulate: true, set_cpsr: true, destination_high: r(9), destination_low: r(10), multiplicand1: r(1), multiplicand2: r(0) } => "smlaleqs r10,r9,r0,r1",
    );
}

#[test]
fn psr_to_register_transfer() {
    decode_succeeds!(
        PsrRegisterTransfer,
        0xE10F1000 => PsrRegisterTransfer { condition: Always, use_spsr: false, destination: r(1) } => "mrs r1,cpsr",
        0xE14F1000 => PsrRegisterTransfer { condition: Always, use_spsr: true, destination: r(1) } => "mrs r1,spsr",
        0x614FC000 => PsrRegisterTransfer { condition: Overflow, use_spsr: true, destination: r(12) } => "mrsvs r12,spsr",
    );
}

#[test]
fn register_to_psr_transfer() {
    use DataOperand::*;
    use ShiftType::*;

    decode_succeeds!(
        RegisterPsrTransfer,
        // Permutations of control bits, register operand.
        0xE129F004 => RegisterPsrTransfer { condition: Always, use_spsr: false, flags_only: false, source: ShiftImmediate(LogicalShiftLeft, 0, r(4)) } => "msr cpsr,r4",
        0xE169F004 => RegisterPsrTransfer { condition: Always, use_spsr: true, flags_only: false, source: ShiftImmediate(LogicalShiftLeft, 0, r(4)) } => "msr spsr,r4",
        0xE128F004 => RegisterPsrTransfer { condition: Always, use_spsr: false, flags_only: true, source: ShiftImmediate(LogicalShiftLeft, 0, r(4)) } => "msr cpsr_flg,r4",
        0xE168F004 => RegisterPsrTransfer { condition: Always, use_spsr: true, flags_only: true, source: ShiftImmediate(LogicalShiftLeft, 0, r(4)) } => "msr spsr_flg,r4",
        // Immediate operands for flag transfer.
        0xE328FC0F => RegisterPsrTransfer { condition: Always, use_spsr: false, flags_only: true, source: Immediate(0xF00) } => "msr cpsr_flg,#0xF00",
        0x4368FC0F => RegisterPsrTransfer { condition: Negative, use_spsr: true, flags_only: true, source: Immediate(0xF00) } => "msrmi spsr_flg,#0xF00",
    );
}

#[test]
fn single_data_swap() {
    decode_succeeds!(
        SingleDataSwap,
        0xE1020091 => SingleDataSwap { condition: Always, swap_byte: false, address: r(2), destination: r(0), source: r(1) } => "swp r0,r1,[r2]",
        0xE1420091 => SingleDataSwap { condition: Always, swap_byte: true, address: r(2), destination: r(0), source: r(1) } => "swpb r0,r1,[r2]",
        0x314AC09B => SingleDataSwap { condition: Lower, swap_byte: true, address: r(10), destination: r(12), source: r(11) } => "swpccb r12,r11,[r10]",
    );
}

#[test]
fn single_data_transfer() {
    use DataOperand::*;
    use ShiftType::*;

    decode_succeeds!(
        SingleDataTransfer,
        // Simplest possible case: load and store a register with no offset in both word and byte mode.
        0xE5943000 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0) } => "ldr r3,[r4]",
        0xE5843000 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(4) }, target: r(3), offset: Immediate(0) } => "str r3,[r4]",
        0xE5D43000 => SingleDataTransfer { condition: Always, transfer_byte: true, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0) } => "ldrb r3,[r4]",
        0xE5C43000 => SingleDataTransfer { condition: Always, transfer_byte: true, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(4) }, target: r(3), offset: Immediate(0) } => "strb r3,[r4]",
        // Pre- and post-indexed immediate offsets.
        0xE5943F00 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) } => "ldr r3,[r4,#+0xF00]",
        0xE5143F00 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) } => "ldr r3,[r4,#-0xF00]",
        0xE5B43F00 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) } => "ldr r3,[r4,#+0xF00]!",
        0xE5343F00 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) } => "ldr r3,[r4,#-0xF00]!",
        0xE4943F00 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) } => "ldr r3,[r4],#+0xF00",
        0xE4143F00 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) } => "ldr r3,[r4],#-0xF00",
        0xE4B43F00 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) } => "ldrt r3,[r4],#+0xF00",
        0xE4EBA437 => SingleDataTransfer { condition: Always, transfer_byte: true, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: false, base: r(11) }, target: r(10), offset: Immediate(0x437) } => "strbt r10,[r11],#+0x437",
        // Pre- and post-indexed shift offsets.  Only immediate shifts are available.
        0xE7943005 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(LogicalShiftLeft, 0, r(5)) } => "ldr r3,[r4,+r5]",
        0xE7143005 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(LogicalShiftLeft, 0, r(5)) } => "ldr r3,[r4,-r5]",
        0xE79433C5 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(ArithmeticShiftRight, 7, r(5)) } => "ldr r3,[r4,+r5,asr #7]",
        0xE7343065 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(RotateRight, 0, r(5)) } => "ldr r3,[r4,-r5,rrx]!",
        0xE6143005 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(LogicalShiftLeft, 0, r(5)) } => "ldr r3,[r4],-r5",
        0xE6943305 => SingleDataTransfer { condition: Always, transfer_byte: false, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(LogicalShiftLeft, 6, r(5)) } => "ldr r3,[r4],+r5,lsl #6",
        // And a kitchen sink instruction.
        0xC66BAFCC => SingleDataTransfer { condition: Greater, transfer_byte: true, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: false, base: r(11) }, target: r(10), offset: ShiftImmediate(ArithmeticShiftRight, 31, r(12)) } => "strgtbt r10,[r11],-r12,asr #31",
    );
}

#[test]
fn software_interrupt() {
    decode_succeeds!(
        SoftwareInterrupt,
        0xEF000000 => SoftwareInterrupt { condition: Always, comment: 0 } => "swi #0x0",
        0x1F00CAFE => SoftwareInterrupt { condition: NotEqual, comment: 0xCAFE } => "swine #0xCAFE",
        0xBF123456 => SoftwareInterrupt { condition: Less, comment: 0x123456 } => "swilt #0x123456",
    );
}
