use crate::decode_succeeds;
use rgba::cpu::instruction::*;

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
        0xE12FFF10 => BranchAndExchange { condition: Always, source: 0 } => "bx r0",
        0x212FFF17 => BranchAndExchange { condition: HigherOrSame, source: 7 } => "bxcs r7",
        0xD12FFF1A => BranchAndExchange { condition: LessOrEqual, source: 10 } => "bxle r10",
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
            operand1: 1,
            destination: 0,
            operand2: ShiftImmediate(LogicalShiftLeft, 0, 2),
        }
    }

    fn simple_data(operand2: DataOperand) -> DataProcessing {
        DataProcessing {
            condition: Condition::Always,
            operation: Add,
            set_cpsr: false,
            operand1: 1,
            destination: 0,
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
        0xE0810382 => simple_data(ShiftImmediate(LogicalShiftLeft, 7, 2)) => "add r0,r1,r2,lsl #7",
        0xE08103A2 => simple_data(ShiftImmediate(LogicalShiftRight, 7, 2)) => "add r0,r1,r2,lsr #7",
        0xE08103C2 => simple_data(ShiftImmediate(ArithmeticShiftRight, 7, 2)) => "add r0,r1,r2,asr #7",
        0xE08103E2 => simple_data(ShiftImmediate(RotateRight, 7, 2)) => "add r0,r1,r2,ror #7",
        0xE0810062 => simple_data(ShiftImmediate(RotateRight, 0, 2)) => "add r0,r1,r2,rrx",
        // Shift operand 2 by a register value.
        0xE0810312 => simple_data(ShiftRegister(LogicalShiftLeft, 3, 2)) => "add r0,r1,r2,lsl r3",
        0xE0810332 => simple_data(ShiftRegister(LogicalShiftRight, 3, 2)) => "add r0,r1,r2,lsr r3",
        0xE0810352 => simple_data(ShiftRegister(ArithmeticShiftRight, 3, 2)) => "add r0,r1,r2,asr r3",
        0xE0810372 => simple_data(ShiftRegister(RotateRight, 3, 2)) => "add r0,r1,r2,ror r3",
        // Using R0 as a ROR operand should not disassemble as RRX.
        0xE0810072 => simple_data(ShiftRegister(RotateRight, 0, 2)) => "add r0,r1,r2,ror r0",
    );
}

#[test]
fn multiply() {
    decode_succeeds!(
        Multiply,
        // Permutations of accumulate and condition code control bits.
        0xE0000192 => Multiply { condition: Always, accumulate: false, set_cpsr: false, destination: 0, addend: 0, multiplicand1: 1, multiplicand2: 2 } => "mul r0,r2,r1",
        0xE0100192 => Multiply { condition: Always, accumulate: false, set_cpsr: true, destination: 0, addend: 0, multiplicand1: 1, multiplicand2: 2 } => "muls r0,r2,r1",
        0xE0201293 => Multiply { condition: Always, accumulate: true, set_cpsr: false, destination: 0, addend: 1, multiplicand1: 2, multiplicand2: 3 } => "mla r0,r3,r2,r1",
        0xE0301293 => Multiply { condition: Always, accumulate: true, set_cpsr: true, destination: 0, addend: 1, multiplicand1: 2, multiplicand2: 3 } => "mlas r0,r3,r2,r1",
        // With some different condition codes.
        0x00314392 => Multiply { condition: Equal, accumulate: true, set_cpsr: true, destination: 1, addend: 4, multiplicand1: 3, multiplicand2: 2 } => "mlaeqs r1,r2,r3,r4",
        0xA0130192 => Multiply { condition: GreaterOrEqual, accumulate: false, set_cpsr: true, destination: 3, addend: 0, multiplicand1: 1, multiplicand2: 2 } => "mulges r3,r2,r1",
    );
}

#[test]
fn multiply_long() {
    decode_succeeds!(
        MultiplyLong,
        // Permutations of all control bits.
        0xE0801392 => MultiplyLong { condition: Always, signed: false, accumulate: false, set_cpsr: false, destination_high: 0, destination_low: 1, multiplicand1: 3, multiplicand2: 2 } => "umull r1,r0,r2,r3",
        0xE0C01392 => MultiplyLong { condition: Always, signed: true, accumulate: false, set_cpsr: false, destination_high: 0, destination_low: 1, multiplicand1: 3, multiplicand2: 2 } => "smull r1,r0,r2,r3",
        0xE0A01392 => MultiplyLong { condition: Always, signed: false, accumulate: true, set_cpsr: false, destination_high: 0, destination_low: 1, multiplicand1: 3, multiplicand2: 2 } => "umlal r1,r0,r2,r3",
        0xE0E01392 => MultiplyLong { condition: Always, signed: true, accumulate: true, set_cpsr: false, destination_high: 0, destination_low: 1, multiplicand1: 3, multiplicand2: 2 } => "smlal r1,r0,r2,r3",
        0xE0901392 => MultiplyLong { condition: Always, signed: false, accumulate: false, set_cpsr: true, destination_high: 0, destination_low: 1, multiplicand1: 3, multiplicand2: 2 } => "umulls r1,r0,r2,r3",
        0xE0D01392 => MultiplyLong { condition: Always, signed: true, accumulate: false, set_cpsr: true, destination_high: 0, destination_low: 1, multiplicand1: 3, multiplicand2: 2 } => "smulls r1,r0,r2,r3",
        0xE0B01392 => MultiplyLong { condition: Always, signed: false, accumulate: true, set_cpsr: true, destination_high: 0, destination_low: 1, multiplicand1: 3, multiplicand2: 2 } => "umlals r1,r0,r2,r3",
        0xE0F01392 => MultiplyLong { condition: Always, signed: true, accumulate: true, set_cpsr: true, destination_high: 0, destination_low: 1, multiplicand1: 3, multiplicand2: 2 } => "smlals r1,r0,r2,r3",
        // With a different condition code, since these mnemonics are becoming alarmingly long.
        0x00F9A190 => MultiplyLong { condition: Equal, signed: true, accumulate: true, set_cpsr: true, destination_high: 9, destination_low: 10, multiplicand1: 1, multiplicand2: 0 } => "smlaleqs r10,r9,r0,r1",
    );
}

#[test]
fn single_data_swap() {
    decode_succeeds!(
        SingleDataSwap,
        0xE1020091 => SingleDataSwap { condition: Always, swap_byte: false, address: 2, destination: 0, source: 1 } => "swp r0,r1,[r2]",
        0xE1420091 => SingleDataSwap { condition: Always, swap_byte: true, address: 2, destination: 0, source: 1 } => "swpb r0,r1,[r2]",
        0x314AC09B => SingleDataSwap { condition: Lower, swap_byte: true, address: 10, destination: 12, source: 11 } => "swpccb r12,r11,[r10]",
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
