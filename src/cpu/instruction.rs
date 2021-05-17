use crate::cpu::{AddressOffset, RegisterNumber};
use derive_more::Display;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use std::fmt;

/// The type of an instruction upon being fetched from memory.  Raw instructions
/// are converted to `Instruction`s in the Decode stage.
pub type RawInstruction = u32;

/// The conditions upon which an instruction can be executed or skipped.  All
/// ARM-mode instructions are subject to conditional execution dependent upon
/// the states of the flags in the CPSR; the specific condition to apply is
/// encoded in the uppermost 4 bits of each instruction (`31:28`).
#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum Condition {
    /// Values are equal (`Z` flag set, suffix `eq`).
    Equal = 0,
    /// Values are not equal (`Z` flag clear, suffix `ne`).
    NotEqual = 1 << 28,
    /// Unsigned greater than or equal (`C` flag set, suffix `cs`).
    HigherOrSame = 2 << 28,
    /// Unsigned less than (`C` flag clear, suffix `cc`).
    Lower = 3 << 28,
    /// Value is negative (`N` flag set, suffix `mi`).
    Negative = 4 << 28,
    /// Value is non-negative (`N` flag clear, suffix `pl`).
    NonNegative = 5 << 28,
    /// Signed operation overflowed (`V` flag set, suffix `vs`).
    Overflow = 6 << 28,
    /// Signed operation did not overflow (`V` flag clear, suffix `vc`).
    NoOverflow = 7 << 28,
    /// Unsigned greater than (`C` set and `Z` clear, suffix `hi`).
    Higher = 8 << 28,
    /// Unsigned less than or equal (`C` clear or `Z` set, suffix `ls`).
    LowerOrSame = 9 << 28,
    /// Signed greater than or equal (`N == V`, suffix `ge`).
    GreaterOrEqual = 10 << 28,
    /// Signed less than (`N != V`, suffix `lt`).
    Less = 11 << 28,
    /// Signed greater than (`Z` flag clear and `N == V`, suffix `gt`).
    Greater = 12 << 28,
    /// Signed less than or equal (`Z` flag set or `N != V`, suffix `le`).
    LessOrEqual = 13 << 28,
    /// Execute unconditionally (suffix `al`).
    Always = 14 << 28,
}

/// The Assembly mnemonics used for each execution condition.
const CONDITION_MNEMONICS: [&str; 15] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "",
];

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", CONDITION_MNEMONICS[(*self as u32 >> 28) as usize])
    }
}

/// Extend the value of the bit in the specified `sign_bit` of the specified
/// `value` through all bits above the sign bit.
fn sign_extend(value: u32, sign_bit: u32) -> i32 {
    let shift = 31 - sign_bit;
    ((value as i32) << shift) >> shift
}

/// A specific type of ARM instruction with a unique encoding scheme.
pub trait InstructionType: fmt::Display + Sized {
    /// Decode the specified instruction to be executed only upon the specified
    /// condition.  If the instruction is invalid for this type, `None` will be
    /// returned.
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Self>;
}

/// A branch instruction, which sets the program counter to an address offset
/// from its current value as specified in the instruction.
#[derive(Debug, Eq, PartialEq)]
pub struct Branch {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// Whether the current value of the program counter should be stored in
    /// `r14` (the *link* register) when this instruction is executed.
    pub link: bool,
    /// The offset from the current program counter to which to branch.  Due to
    /// instruction prefetch, the target address will be 8 bytes beyond that of
    /// the instruction itself; since the pipeline is simulated by `rgba`, this
    /// concern is ignored.
    pub offset: AddressOffset,
}

impl InstructionType for Branch {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Self> {
        let mask = 0x0A00_0000;
        ((raw & mask) == mask).then_some(Self {
            condition,
            // If bit 24 is set, this is a Branch with Link (bl).
            link: raw & (1 << 24) != 0,
            // 24-bit offset must be shifted 2 bits to the right.
            offset: sign_extend(raw << 2, 25),
        })
    }
}

impl fmt::Display for Branch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let link_mnemonic = if self.link { "l" } else { "" };
        write!(f, "b{}{} {:+}", link_mnemonic, self.condition, self.offset)
    }
}

/// An indirect branch instruction that copies the value of a specified register
/// into the program counter.  The *exchange* portion of this instruction refers
/// to the fact that this instruction can switch between ARM and Thumb modes: if
/// the register number is even, the processor will be placed in ARM mode
/// following the branch, and if it is odd, it will be in Thumb mode.
#[derive(Debug, Eq, PartialEq)]
pub struct BranchAndExchange {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// The register whose value will be copied into the program counter.  The
    /// behaviour of this instruction when this register is `r15` is undefined.
    pub source: RegisterNumber,
}

impl InstructionType for BranchAndExchange {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Self> {
        let mask = 0x012F_FF10;
        ((raw & mask) == mask).then_some(Self {
            condition,
            // The register number is encoded in the low nybble of the instruction.
            source: (raw & 0xF) as RegisterNumber,
        })
    }
}

impl fmt::Display for BranchAndExchange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bx{} r{}", self.condition, self.source)
    }
}

/// A decoded instruction, converted from a `RawInstruction` by the decode unit.
/// Contains all information in the instruction required for execution in the
/// Execute stage.
#[derive(Display, Eq, PartialEq)]
pub enum Instruction {
    Branch(Branch),
    BranchAndExchange(BranchAndExchange),
}

impl Instruction {
    /// Decode the specified instruction, if it can be decoded.  If the
    /// instruction is not valid, `None` will be returned.
    pub fn decode(raw: RawInstruction) -> Option<Self> {
        let condition = Condition::from_u32(raw & 0xF000_0000)?;
        Branch::decode(raw, condition)
            .map(Self::Branch)
            .or_else(|| BranchAndExchange::decode(raw, condition).map(Self::BranchAndExchange))
    }
}

impl fmt::Debug for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
