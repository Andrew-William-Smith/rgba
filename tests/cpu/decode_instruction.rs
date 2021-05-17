use crate::decode_succeeds;
use rgba::cpu::instruction::{Branch, Condition, Instruction};

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
        // Branch without link, forward and backward offsets.
        0xEA000000 => Branch, Branch { condition: Condition::Always, link: false, offset: 0 } => "b +0",
        0x1A000000 => Branch, Branch { condition: Condition::NotEqual, link: false, offset: 0 } => "bne +0",
        0xEA00CAFE => Branch, Branch { condition: Condition::Always, link: false, offset: 207_864 } => "b +207864",
        0x6AF0000F => Branch, Branch { condition: Condition::Overflow, link: false, offset: -4_194_244 } => "bvs -4194244",
        // Branch with link.
        0xEB000000 => Branch, Branch { condition: Condition::Always, link: true, offset: 0 } => "bl +0",
        0x0B00BEEF => Branch, Branch { condition: Condition::Equal, link: true, offset: 195_516 } => "bleq +195516",
        0x3B808080 => Branch, Branch { condition: Condition::Lower, link: true, offset: -33_422_848 } => "blcc -33422848",
    );
}
