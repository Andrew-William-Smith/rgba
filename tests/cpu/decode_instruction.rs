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
        0xEA000000 => Branch { condition: Condition::Always, link: false, offset: 0 } => "b #+0",
        0x1A000000 => Branch { condition: Condition::NotEqual, link: false, offset: 0 } => "bne #+0",
        0xEA00CAFE => Branch { condition: Condition::Always, link: false, offset: 207_864 } => "b #+207864",
        0x6AF0000F => Branch { condition: Condition::Overflow, link: false, offset: -4_194_244 } => "bvs #-4194244",
        // Branch with link.
        0xEB000000 => Branch { condition: Condition::Always, link: true, offset: 0 } => "bl #+0",
        0x0B00BEEF => Branch { condition: Condition::Equal, link: true, offset: 195_516 } => "bleq #+195516",
        0x3B808080 => Branch { condition: Condition::Lower, link: true, offset: -33_422_848 } => "blcc #-33422848",
    );
}

#[test]
fn branch_and_exchange() {
    decode_succeeds!(
        BranchAndExchange,
        0xE12FFF10 => BranchAndExchange { condition: Condition::Always, source: 0 } => "bx r0",
        0x212FFF17 => BranchAndExchange { condition: Condition::HigherOrSame, source: 7 } => "bxcs r7",
        0xD12FFF1A => BranchAndExchange { condition: Condition::LessOrEqual, source: 10 } => "bxle r10",
    );
}

#[test]
fn multiply() {
    decode_succeeds!(
        Multiply,
        // Permutations of accumulate and condition code control bits.
        0xE0000192 => Multiply { condition: Condition::Always, accumulate: false, set_cpsr: false, destination: 0, addend: 0, multiplicand1: 1, multiplicand2: 2 } => "mul r0,r2,r1",
        0xE0100192 => Multiply { condition: Condition::Always, accumulate: false, set_cpsr: true, destination: 0, addend: 0, multiplicand1: 1, multiplicand2: 2 } => "muls r0,r2,r1",
        0xE0201293 => Multiply { condition: Condition::Always, accumulate: true, set_cpsr: false, destination: 0, addend: 1, multiplicand1: 2, multiplicand2: 3 } => "mla r0,r3,r2,r1",
        0xE0301293 => Multiply { condition: Condition::Always, accumulate: true, set_cpsr: true, destination: 0, addend: 1, multiplicand1: 2, multiplicand2: 3 } => "mlas r0,r3,r2,r1",
        // With some different condition codes.
        0x00314392 => Multiply { condition: Condition::Equal, accumulate: true, set_cpsr: true, destination: 1, addend: 4, multiplicand1: 3, multiplicand2: 2 } => "mlaeqs r1,r2,r3,r4",
        0xA0130192 => Multiply { condition: Condition::GreaterOrEqual, accumulate: false, set_cpsr: true, destination: 3, addend: 0, multiplicand1: 1, multiplicand2: 2 } => "mulges r3,r2,r1",
    );
}

#[test]
fn software_interrupt() {
    decode_succeeds!(
        SoftwareInterrupt,
        0xEF000000 => SoftwareInterrupt { condition: Condition::Always, comment: 0 } => "swi #0x0",
        0x1F00CAFE => SoftwareInterrupt { condition: Condition::NotEqual, comment: 0xCAFE } => "swine #0xCAFE",
        0xBF123456 => SoftwareInterrupt { condition: Condition::Less, comment: 0x123456 } => "swilt #0x123456",
    );
}
