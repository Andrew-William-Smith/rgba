use crate::decode_succeeds;
use rgba::cpu::{instruction::*, CoprocessorRegister, RegisterNumber};

/// Shorthand for defining a register number, since we use them **everywhere**.
const fn r(number: u8) -> RegisterNumber {
    RegisterNumber(number)
}

/// Shorthand for defining a coprocessor register number.
const fn c(number: u8) -> CoprocessorRegister {
    CoprocessorRegister(number)
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
        0xE9BDE00F => "ldmed sp!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0xE00F },
        0xE8BDE00F => "ldmfd sp!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0xE00F },
        0xE93DE00F => "ldmea sp!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: true, base: r(13) }, registers: 0xE00F },
        0xE83DE00F => "ldmfa sp!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: true, base: r(13) }, registers: 0xE00F },
        0xE9ADE00F => "stmfa sp!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: false, base: r(13) }, registers: 0xE00F },
        0xE8ADE00F => "stmea sp!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: false, base: r(13) }, registers: 0xE00F },
        0xE92DE00F => "stmfd sp!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: false, base: r(13) }, registers: 0xE00F },
        0xE82DE00F => "stmed sp!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: false, base: r(13) }, registers: 0xE00F },
        // Mnemonics for non-stack operations.
        0xE9B7E00F => "ldmib r7!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(7) }, registers: 0xE00F },
        0xE8B7E00F => "ldmia r7!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: true, base: r(7) }, registers: 0xE00F },
        0xE937E00F => "ldmdb r7!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: true, base: r(7) }, registers: 0xE00F },
        0xE837E00F => "ldmda r7!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: true, base: r(7) }, registers: 0xE00F },
        0xE9A7E00F => "stmib r7!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: false, base: r(7) }, registers: 0xE00F },
        0xE8A7E00F => "stmia r7!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: false, base: r(7) }, registers: 0xE00F },
        0xE927E00F => "stmdb r7!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: false, base: r(7) }, registers: 0xE00F },
        0xE827E00F => "stmda r7!,{r0-r3,sp-pc}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: false, base: r(7) }, registers: 0xE00F },
        // Alternate banking modes.
        0xE9D08000 => "ldmib r0,{pc}^" => BlockDataTransfer { condition: Always, mode: LoadSpsr, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(0) }, registers: 0x8000 },
        0xE9C08000 => "stmib r0,{pc}^" => BlockDataTransfer { condition: Always, mode: UserBank, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(0) }, registers: 0x8000 },
        0xE9D00008 => "ldmib r0,{r3}^" => BlockDataTransfer { condition: Always, mode: UserBank, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(0) }, registers: 0x0008 },
        0xE9C00008 => "stmib r0,{r3}^" => BlockDataTransfer { condition: Always, mode: UserBank, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(0) }, registers: 0x0008 },
        // Register formatting in disassembly.
        0x59BD5555 => "ldmpled sp!,{r0,r2,r4,r6,r8,r10,r12,lr}" => BlockDataTransfer { condition: NonNegative, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0x5555 },
        0x99BDAAAA => "ldmlsed sp!,{r1,r3,r5,r7,r9,r11,sp,pc}" => BlockDataTransfer { condition: LowerOrSame, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0xAAAA },
        0xE9BD7777 => "ldmed sp!,{r0-r2,r4-r6,r8-r10,r12-lr}" => BlockDataTransfer { condition: Always, mode: Normal, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(13) }, registers: 0x7777 },
    );
}

#[test]
fn branches() {
    decode_succeeds!(
        Branch,
        // Branch without link, forward and backward offsets.
        0xEA000000 => "b #+0" => Branch { condition: Always, link: false, offset: 0 },
        0x1A000000 => "bne #+0" => Branch { condition: NotEqual, link: false, offset: 0 },
        0xEA00CAFE => "b #+207864" => Branch { condition: Always, link: false, offset: 207_864 },
        0x6AF0000F => "bvs #-4194244" => Branch { condition: Overflow, link: false, offset: -4_194_244 },
        // Branch with link.
        0xEB000000 => "bl #+0" => Branch { condition: Always, link: true, offset: 0 },
        0x0B00BEEF => "bleq #+195516" => Branch { condition: Equal, link: true, offset: 195_516 },
        0x3B808080 => "blcc #-33422848" => Branch { condition: Lower, link: true, offset: -33_422_848 },
    );
}

#[test]
fn branch_and_exchange() {
    decode_succeeds!(
        BranchAndExchange,
        0xE12FFF10 => "bx r0" => BranchAndExchange { condition: Always, source: r(0) },
        0x212FFF17 => "bxcs r7" => BranchAndExchange { condition: HigherOrSame, source: r(7) },
        0xD12FFF1A => "bxle r10" => BranchAndExchange { condition: LessOrEqual, source: r(10) },
    );
}

#[test]
fn coprocessor_data_transfer() {
    use DataOperand::*;

    decode_succeeds!(
        CoprocessorDataTransfer,
        // All variations of mnemonics.
        0xED932100 => "ldc p1,c2,[r3]" => CoprocessorDataTransfer { condition: Always, transfer_length: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(3) }, target: c(2), coprocessor: 1, offset: Immediate(0) },
        0xEDD32100 => "ldcl p1,c2,[r3]" => CoprocessorDataTransfer { condition: Always, transfer_length: true, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(3) }, target: c(2), coprocessor: 1, offset: Immediate(0) },
        0xED832100 => "stc p1,c2,[r3]" => CoprocessorDataTransfer { condition: Always, transfer_length: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(3) }, target: c(2), coprocessor: 1, offset: Immediate(0) },
        0xEDC32100 => "stcl p1,c2,[r3]" => CoprocessorDataTransfer { condition: Always, transfer_length: true, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(3) }, target: c(2), coprocessor: 1, offset: Immediate(0) },
        // Various addressing modes.
        0xED998789 => "ldc p7,c8,[r9,#+0x224]" => CoprocessorDataTransfer { condition: Always, transfer_length: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(9) }, target: c(8), coprocessor: 7, offset: Immediate(0x224) },
        0xED198789 => "ldc p7,c8,[r9,#-0x224]" => CoprocessorDataTransfer { condition: Always, transfer_length: false, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: false, load: true, base: r(9) }, target: c(8), coprocessor: 7, offset: Immediate(0x224) },
        0xEDB98789 => "ldc p7,c8,[r9,#+0x224]!" => CoprocessorDataTransfer { condition: Always, transfer_length: false, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(9) }, target: c(8), coprocessor: 7, offset: Immediate(0x224) },
        0xEC398789 => "ldc p7,c8,[r9],#-0x224" => CoprocessorDataTransfer { condition: Always, transfer_length: false, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: true, base: r(9) }, target: c(8), coprocessor: 7, offset: Immediate(0x224) },
        0x0DE210FF => "stceql p0,c1,[r2,#+0x3FC]!" => CoprocessorDataTransfer { condition: Equal, transfer_length: true, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: false, base: r(2) }, target: c(1), coprocessor: 0, offset: Immediate(0x3FC) },
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
        0xE0010002 => "and r0,r1,r2" => simple_instruction(And, false),
        0xE0210002 => "eor r0,r1,r2" => simple_instruction(ExclusiveOr, false),
        0xE0410002 => "sub r0,r1,r2" => simple_instruction(Subtract, false),
        0xE0610002 => "rsb r0,r1,r2" => simple_instruction(ReverseSubtract, false),
        0xE0810002 => "add r0,r1,r2" => simple_instruction(Add, false),
        0xE0A10002 => "adc r0,r1,r2" => simple_instruction(AddWithCarry, false),
        0xE0C10002 => "sbc r0,r1,r2" => simple_instruction(SubtractWithCarry, false),
        0xE0E10002 => "rsc r0,r1,r2" => simple_instruction(ReverseSubtractWithCarry, false),
        0xE1010002 => "tst r1,r2" => simple_instruction(Test, false),
        0xE1210002 => "teq r1,r2" => simple_instruction(TestEqual, false),
        0xE1410002 => "cmp r1,r2" => simple_instruction(CompareSubtract, false),
        0xE1610002 => "cmn r1,r2" => simple_instruction(CompareAdd, false),
        0xE1810002 => "orr r0,r1,r2" => simple_instruction(InclusiveOr, false),
        0xE1A10002 => "mov r0,r2" => simple_instruction(Move, false),
        0xE1C10002 => "bic r0,r1,r2" => simple_instruction(BitClear, false),
        0xE1E10002 => "mvn r0,r2" => simple_instruction(MoveInverse, false),
        // Simple opcodes with the CPSR flag set; comparisons should not change.
        0xE0110002 => "ands r0,r1,r2" => simple_instruction(And, true),
        0xE0310002 => "eors r0,r1,r2" => simple_instruction(ExclusiveOr, true),
        0xE0510002 => "subs r0,r1,r2" => simple_instruction(Subtract, true),
        0xE0710002 => "rsbs r0,r1,r2" => simple_instruction(ReverseSubtract, true),
        0xE0910002 => "adds r0,r1,r2" => simple_instruction(Add, true),
        0xE0B10002 => "adcs r0,r1,r2" => simple_instruction(AddWithCarry, true),
        0xE0D10002 => "sbcs r0,r1,r2" => simple_instruction(SubtractWithCarry, true),
        0xE0F10002 => "rscs r0,r1,r2" => simple_instruction(ReverseSubtractWithCarry, true),
        0xE1110002 => "tst r1,r2" => simple_instruction(Test, true),
        0xE1310002 => "teq r1,r2" => simple_instruction(TestEqual, true),
        0xE1510002 => "cmp r1,r2" => simple_instruction(CompareSubtract, true),
        0xE1710002 => "cmn r1,r2" => simple_instruction(CompareAdd, true),
        0xE1910002 => "orrs r0,r1,r2" => simple_instruction(InclusiveOr, true),
        0xE1B10002 => "movs r0,r2" => simple_instruction(Move, true),
        0xE1D10002 => "bics r0,r1,r2" => simple_instruction(BitClear, true),
        0xE1F10002 => "mvns r0,r2" => simple_instruction(MoveInverse, true),
        // Immediate operand.
        0xE2810C0F => "add r0,r1,#0xF00" => simple_data(Immediate(0xF00)),
        // Shift operand 2 by an immediate value.
        0xE0810382 => "add r0,r1,r2,lsl #7" => simple_data(ShiftImmediate(LogicalShiftLeft, 7, r(2))),
        0xE08103A2 => "add r0,r1,r2,lsr #7" => simple_data(ShiftImmediate(LogicalShiftRight, 7, r(2))),
        0xE08103C2 => "add r0,r1,r2,asr #7" => simple_data(ShiftImmediate(ArithmeticShiftRight, 7, r(2))),
        0xE08103E2 => "add r0,r1,r2,ror #7" => simple_data(ShiftImmediate(RotateRight, 7, r(2))),
        0xE0810062 => "add r0,r1,r2,rrx" => simple_data(ShiftImmediate(RotateRight, 0, r(2))),
        // Shift operand 2 by a register value.
        0xE0810312 => "add r0,r1,r2,lsl r3" => simple_data(ShiftRegister(LogicalShiftLeft, r(3), r(2))),
        0xE0810332 => "add r0,r1,r2,lsr r3" => simple_data(ShiftRegister(LogicalShiftRight, r(3), r(2))),
        0xE0810352 => "add r0,r1,r2,asr r3" => simple_data(ShiftRegister(ArithmeticShiftRight, r(3), r(2))),
        0xE0810372 => "add r0,r1,r2,ror r3" => simple_data(ShiftRegister(RotateRight, r(3), r(2))),
        // Using R0 as a ROR operand should not disassemble as RRX.
        0xE0810072 => "add r0,r1,r2,ror r0" => simple_data(ShiftRegister(RotateRight, r(0), r(2))),
    );
}

#[test]
fn multiply() {
    decode_succeeds!(
        Multiply,
        // Permutations of accumulate and condition code control bits.
        0xE0000192 => "mul r0,r2,r1" => Multiply { condition: Always, accumulate: false, set_cpsr: false, destination: r(0), addend: r(0), multiplicand1: r(1), multiplicand2: r(2) },
        0xE0100192 => "muls r0,r2,r1" => Multiply { condition: Always, accumulate: false, set_cpsr: true, destination: r(0), addend: r(0), multiplicand1: r(1), multiplicand2: r(2) },
        0xE0201293 => "mla r0,r3,r2,r1" => Multiply { condition: Always, accumulate: true, set_cpsr: false, destination: r(0), addend: r(1), multiplicand1: r(2), multiplicand2: r(3) },
        0xE0301293 => "mlas r0,r3,r2,r1" => Multiply { condition: Always, accumulate: true, set_cpsr: true, destination: r(0), addend: r(1), multiplicand1: r(2), multiplicand2: r(3) },
        // With some different condition codes.
        0x00314392 => "mlaeqs r1,r2,r3,r4" => Multiply { condition: Equal, accumulate: true, set_cpsr: true, destination: r(1), addend: r(4), multiplicand1: r(3), multiplicand2: r(2) },
        0xA0130192 => "mulges r3,r2,r1" => Multiply { condition: GreaterOrEqual, accumulate: false, set_cpsr: true, destination: r(3), addend: r(0), multiplicand1: r(1), multiplicand2: r(2) },
    );
}

#[test]
fn multiply_long() {
    decode_succeeds!(
        MultiplyLong,
        // Permutations of all control bits.
        0xE0801392 => "umull r1,r0,r2,r3" => MultiplyLong { condition: Always, signed: false, accumulate: false, set_cpsr: false, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) },
        0xE0C01392 => "smull r1,r0,r2,r3" => MultiplyLong { condition: Always, signed: true, accumulate: false, set_cpsr: false, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) },
        0xE0A01392 => "umlal r1,r0,r2,r3" => MultiplyLong { condition: Always, signed: false, accumulate: true, set_cpsr: false, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) },
        0xE0E01392 => "smlal r1,r0,r2,r3" => MultiplyLong { condition: Always, signed: true, accumulate: true, set_cpsr: false, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) },
        0xE0901392 => "umulls r1,r0,r2,r3" => MultiplyLong { condition: Always, signed: false, accumulate: false, set_cpsr: true, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) },
        0xE0D01392 => "smulls r1,r0,r2,r3" => MultiplyLong { condition: Always, signed: true, accumulate: false, set_cpsr: true, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) },
        0xE0B01392 => "umlals r1,r0,r2,r3" => MultiplyLong { condition: Always, signed: false, accumulate: true, set_cpsr: true, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) },
        0xE0F01392 => "smlals r1,r0,r2,r3" => MultiplyLong { condition: Always, signed: true, accumulate: true, set_cpsr: true, destination_high: r(0), destination_low: r(1), multiplicand1: r(3), multiplicand2: r(2) },
        // With a different condition code, since these mnemonics are becoming alarmingly long.
        0x00F9A190 => "smlaleqs r10,r9,r0,r1" => MultiplyLong { condition: Equal, signed: true, accumulate: true, set_cpsr: true, destination_high: r(9), destination_low: r(10), multiplicand1: r(1), multiplicand2: r(0) },
    );
}

#[test]
fn psr_to_register_transfer() {
    decode_succeeds!(
        PsrRegisterTransfer,
        0xE10F1000 => "mrs r1,cpsr" => PsrRegisterTransfer { condition: Always, use_spsr: false, destination: r(1) },
        0xE14F1000 => "mrs r1,spsr" => PsrRegisterTransfer { condition: Always, use_spsr: true, destination: r(1) },
        0x614FC000 => "mrsvs r12,spsr" => PsrRegisterTransfer { condition: Overflow, use_spsr: true, destination: r(12) },
    );
}

#[test]
fn register_to_psr_transfer() {
    use DataOperand::*;
    use ShiftType::*;

    decode_succeeds!(
        RegisterPsrTransfer,
        // Permutations of control bits, register operand.
        0xE129F004 => "msr cpsr,r4" => RegisterPsrTransfer { condition: Always, use_spsr: false, flags_only: false, source: ShiftImmediate(LogicalShiftLeft, 0, r(4)) },
        0xE169F004 => "msr spsr,r4" => RegisterPsrTransfer { condition: Always, use_spsr: true, flags_only: false, source: ShiftImmediate(LogicalShiftLeft, 0, r(4)) },
        0xE128F004 => "msr cpsr_flg,r4" => RegisterPsrTransfer { condition: Always, use_spsr: false, flags_only: true, source: ShiftImmediate(LogicalShiftLeft, 0, r(4)) },
        0xE168F004 => "msr spsr_flg,r4" => RegisterPsrTransfer { condition: Always, use_spsr: true, flags_only: true, source: ShiftImmediate(LogicalShiftLeft, 0, r(4)) },
        // Immediate operands for flag transfer.
        0xE328FC0F => "msr cpsr_flg,#0xF00" => RegisterPsrTransfer { condition: Always, use_spsr: false, flags_only: true, source: Immediate(0xF00) },
        0x4368FC0F => "msrmi spsr_flg,#0xF00" => RegisterPsrTransfer { condition: Negative, use_spsr: true, flags_only: true, source: Immediate(0xF00) },
    );
}

#[test]
fn single_data_swap() {
    decode_succeeds!(
        SingleDataSwap,
        0xE1020091 => "swp r0,r1,[r2]" => SingleDataSwap { condition: Always, swap_byte: false, address: r(2), destination: r(0), source: r(1) },
        0xE1420091 => "swpb r0,r1,[r2]" => SingleDataSwap { condition: Always, swap_byte: true, address: r(2), destination: r(0), source: r(1) },
        0x314AC09B => "swpccb r12,r11,[r10]" => SingleDataSwap { condition: Lower, swap_byte: true, address: r(10), destination: r(12), source: r(11) },
    );
}

#[test]
fn single_data_transfer() {
    use DataOperand::*;
    use ShiftType::*;
    use SingleTransferType::*;

    decode_succeeds!(
        SingleDataTransfer,
        // Simplest possible case: load and store a register with no offset in both word and byte mode.
        0xE5943000 => "ldr r3,[r4]" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0) },
        0xE5843000 => "str r3,[r4]" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(4) }, target: r(3), offset: Immediate(0) },
        0xE5D43000 => "ldrb r3,[r4]" => SingleDataTransfer { condition: Always, transfer_type: UnsignedByte, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0) },
        0xE5C43000 => "strb r3,[r4]" => SingleDataTransfer { condition: Always, transfer_type: UnsignedByte, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(4) }, target: r(3), offset: Immediate(0) },
        // Pre- and post-indexed immediate offsets.
        0xE5943F00 => "ldr r3,[r4,#+0xF00]" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) },
        0xE5143F00 => "ldr r3,[r4,#-0xF00]" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) },
        0xE5B43F00 => "ldr r3,[r4,#+0xF00]!" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: true, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) },
        0xE5343F00 => "ldr r3,[r4,#-0xF00]!" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) },
        0xE4943F00 => "ldr r3,[r4],#+0xF00" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) },
        0xE4143F00 => "ldr r3,[r4],#-0xF00" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: false, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) },
        0xE4B43F00 => "ldrt r3,[r4],#+0xF00" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: true, base: r(4) }, target: r(3), offset: Immediate(0xF00) },
        0xE4EBA437 => "strbt r10,[r11],#+0x437" => SingleDataTransfer { condition: Always, transfer_type: UnsignedByte, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: true, load: false, base: r(11) }, target: r(10), offset: Immediate(0x437) },
        // Pre- and post-indexed shift offsets.  Only immediate shifts are available.
        0xE7943005 => "ldr r3,[r4,+r5]" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(LogicalShiftLeft, 0, r(5)) },
        0xE7143005 => "ldr r3,[r4,-r5]" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(LogicalShiftLeft, 0, r(5)) },
        0xE79433C5 => "ldr r3,[r4,+r5,asr #7]" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(ArithmeticShiftRight, 7, r(5)) },
        0xE7343065 => "ldr r3,[r4,-r5,rrx]!" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(RotateRight, 0, r(5)) },
        0xE6143005 => "ldr r3,[r4],-r5" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(LogicalShiftLeft, 0, r(5)) },
        0xE6943305 => "ldr r3,[r4],+r5,lsl #6" => SingleDataTransfer { condition: Always, transfer_type: Word, opt: DataTransferOptions { pre_index: false, add_offset: true, write_back: false, load: true, base: r(4) }, target: r(3), offset: ShiftImmediate(LogicalShiftLeft, 6, r(5)) },
        // And a kitchen sink instruction.
        0xC66BAFCC => "strgtbt r10,[r11],-r12,asr #31" => SingleDataTransfer { condition: Greater, transfer_type: UnsignedByte, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: true, load: false, base: r(11) }, target: r(10), offset: ShiftImmediate(ArithmeticShiftRight, 31, r(12)) },
    );
}

#[test]
fn single_data_transfer_alternate() {
    use DataOperand::*;
    use ShiftType::*;
    use SingleTransferType::*;

    decode_succeeds!(
        SingleDataTransfer,
        // All mnemonics for transfer sizes and sign extension.
        0xE1D760B0 => "ldrh r6,[r7]" => SingleDataTransfer { condition: Always, transfer_type: UnsignedHalfWord, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(7) }, target: r(6), offset: Immediate(0) },
        0xE1C760B0 => "strh r6,[r7]" => SingleDataTransfer { condition: Always, transfer_type: UnsignedHalfWord, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(7) }, target: r(6), offset: Immediate(0) },
        0xE1D760F0 => "ldrsh r6,[r7]" => SingleDataTransfer { condition: Always, transfer_type: SignedHalfWord, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(7) }, target: r(6), offset: Immediate(0) },
        0xE1D760D0 => "ldrsb r6,[r7]" => SingleDataTransfer { condition: Always, transfer_type: SignedByte, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(7) }, target: r(6), offset: Immediate(0) },
        // Examples from the ARM manual.
        0xE13210B3 => "ldrh r1,[r2,-r3]!" => SingleDataTransfer { condition: Always, transfer_type: UnsignedHalfWord, opt: DataTransferOptions { pre_index: true, add_offset: false, write_back: true, load: true, base: r(2) }, target: r(1), offset: ShiftImmediate(LogicalShiftLeft, 0, r(3)) },
        0xE1C430BE => "strh r3,[r4,#+0xE]" => SingleDataTransfer { condition: Always, transfer_type: UnsignedHalfWord, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(4) }, target: r(3), offset: Immediate(0xE) },
        0xE0528DDF => "ldrsb r8,[r2],#-0xDF" => SingleDataTransfer { condition: Always, transfer_type: SignedByte, opt: DataTransferOptions { pre_index: false, add_offset: false, write_back: false, load: true, base: r(2) }, target: r(8), offset: Immediate(0xDF) },
        0x11D0B0F0 => "ldrnesh r11,[r0]" => SingleDataTransfer { condition: NotEqual, transfer_type: SignedHalfWord, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: true, base: r(0) }, target: r(11), offset: Immediate(0) },
        0xE1CF5AB7 => "strh r5,[pc,#+0xA7]" => SingleDataTransfer { condition: Always, transfer_type: UnsignedHalfWord, opt: DataTransferOptions { pre_index: true, add_offset: true, write_back: false, load: false, base: r(15) }, target: r(5), offset: Immediate(0xA7) },
    );
}

#[test]
fn software_interrupt() {
    decode_succeeds!(
        SoftwareInterrupt,
        0xEF000000 => "swi #0x0" => SoftwareInterrupt { condition: Always, comment: 0 },
        0x1F00CAFE => "swine #0xCAFE" => SoftwareInterrupt { condition: NotEqual, comment: 0xCAFE },
        0xBF123456 => "swilt #0x123456" => SoftwareInterrupt { condition: Less, comment: 0x123456 },
    );
}
