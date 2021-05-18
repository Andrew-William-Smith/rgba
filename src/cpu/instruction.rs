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

/// Determine whether the bit at the specified `index`, counted from the least
/// significant bit, is set in the specified `value`.
fn bit_is_set(value: u32, index: u8) -> bool {
    value & (1 << index) != 0
}

/// Select the specified number of bits (`size`) beginning at the specified
/// `low_bit` index in the specified `value`.  The resulting value will feature
/// the low bit shifted into index `0`.
fn select_bits(value: u32, low_bit: u8, size: u8) -> u32 {
    (value >> low_bit) & ((1 << size) - 1)
}

/// Extend the value of the bit in the specified `sign_bit` of the specified
/// `value` through all bits above the sign bit.
fn sign_extend(value: u32, sign_bit: u8) -> i32 {
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
        ((raw & 0x0E00_0000) == 0x0A00_0000).then_some(Self {
            condition,
            // If bit 24 is set, this is a Branch with Link (bl).
            link: bit_is_set(raw, 24),
            // 24-bit offset must be shifted 2 bits to the right.
            offset: sign_extend(raw << 2, 25),
        })
    }
}

impl fmt::Display for Branch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let link_mnemonic = if self.link { "l" } else { "" };
        write!(f, "b{}{} #{:+}", link_mnemonic, self.condition, self.offset)
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
        ((raw & 0x0FFF_FFF0) == 0x012F_FF10).then_some(Self {
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

/// A multiply or multiply-accumulate instruction, which multiplies the
/// specified integer operands (`mul`) and may optionally also add the value of
/// an additional register to the result (`mla`).  As with all arithmetic
/// operations, this operation may or may not modify the CPSR as specified.
#[derive(Debug, Eq, PartialEq)]
pub struct Multiply {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// Whether the addend register should be added to the result of the
    /// multiply operation (mnemonic `mla`).
    pub accumulate: bool,
    /// Whether the condition codes in the CPSR should be affected as a result
    /// of this operation.
    pub set_cpsr: bool,
    /// The register `Rd` in which the product should be stored.
    pub destination: RegisterNumber,
    /// The register `Rn` from which the addend of this operation should be
    /// sourced when `accumulate` is `true`.
    pub addend: RegisterNumber,
    /// The register `Rs` from which the first multiplicand should be sourced.
    pub multiplicand1: RegisterNumber,
    /// The register `Rm` from which the second multiplicand should be sourced.
    pub multiplicand2: RegisterNumber,
}

impl InstructionType for Multiply {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Self> {
        ((raw & 0x0FC0_00F0) == 0x0000_0090).then_some(Self {
            condition,
            accumulate: bit_is_set(raw, 21),
            set_cpsr: bit_is_set(raw, 20),
            destination: select_bits(raw, 16, 4) as RegisterNumber,
            addend: select_bits(raw, 12, 4) as RegisterNumber,
            multiplicand1: select_bits(raw, 8, 4) as RegisterNumber,
            multiplicand2: (raw & 0xF) as RegisterNumber,
        })
    }
}

impl fmt::Display for Multiply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let suffix = if self.set_cpsr { "s" } else { "" };
        let common = format!(
            "{}{} r{},r{},r{}",
            self.condition, suffix, self.destination, self.multiplicand2, self.multiplicand1
        );

        if self.accumulate {
            write!(f, "mla{},r{}", common, self.addend)
        } else {
            write!(f, "mul{}", common)
        }
    }
}

/// A 64-bit multiply or multiply-accumulate operation, which multiplies the
/// specified integer operands and optionally adds an extra 64-bit value to the
/// result.  Unlike 32-bit multiplications, these instructions may perform
/// either signed or unsigned multiplication, resulting in four distinct
/// mnemonics: `umull`, `smull`, `umlal`, and `smlal`.
#[derive(Debug, Eq, PartialEq)]
pub struct MultiplyLong {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// Whether the multiplicands should be considered signed or unsigned.
    pub signed: bool,
    /// Whether the values of the destination registers combined into a 64-bit
    /// value `(RdHi,RdLo)` should be added to the result of the multiplication.
    pub accumulate: bool,
    /// Whether the condition codes in the CPSR should be affected as a result
    /// of this operation.
    pub set_cpsr: bool,
    /// The register `RdHi` in which the high 32 bits of the product should be
    /// stored, and from which the high 32 bits of the addend will be sourced if
    /// `accumulate` is `true`.
    pub destination_high: RegisterNumber,
    /// The register `RdLo` in which the low 32 bits of the product should be
    /// stored, and from which the low 32 bits of the addend will be sourced if
    /// `accumulate` is `true`.
    pub destination_low: RegisterNumber,
    /// The register `Rs` from which the first multiplicand should be sourced.
    pub multiplicand1: RegisterNumber,
    /// The register `Rm` from which the second multiplicand should be sourced.
    pub multiplicand2: RegisterNumber,
}

impl InstructionType for MultiplyLong {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Self> {
        ((raw & 0x0F80_00F0) == 0x0080_0090).then_some(Self {
            condition,
            signed: bit_is_set(raw, 22),
            accumulate: bit_is_set(raw, 21),
            set_cpsr: bit_is_set(raw, 20),
            destination_high: select_bits(raw, 16, 4) as RegisterNumber,
            destination_low: select_bits(raw, 12, 4) as RegisterNumber,
            multiplicand1: select_bits(raw, 8, 4) as RegisterNumber,
            multiplicand2: (raw & 0xF) as RegisterNumber,
        })
    }
}

impl fmt::Display for MultiplyLong {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sign_prefix = if self.signed { "s" } else { "u" };
        let mnemonic = if self.accumulate { "mlal" } else { "mull" };
        let suffix = if self.set_cpsr { "s" } else { "" };

        write!(
            f,
            "{}{}{}{} r{},r{},r{},r{}",
            sign_prefix,
            mnemonic,
            self.condition,
            suffix,
            self.destination_low,
            self.destination_high,
            self.multiplicand2,
            self.multiplicand1
        )
    }
}

/// An atomic data swap of either an entire word or a single byte.  On
/// multiprocessor systems, the bus is locked for the entire duration of this
/// instruction; however, on the uniprocessor GBA, this instruction is exactly
/// identical to an `ldr` followed by an `str`.
#[derive(Debug, Eq, PartialEq)]
pub struct SingleDataSwap {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// Whether this instruction should swap an entire word at once (`false`) or
    /// only a single byte (`true`).
    pub swap_byte: bool,
    /// The base register `Rn` in which the memory address of the quantity to
    /// swap is stored.
    pub address: RegisterNumber,
    /// The register `Rd` in which the old contents of memory at the target
    /// `address` should be stored following the swap.
    pub destination: RegisterNumber,
    /// The register `Rm` whose contents should be written to memory at the
    /// target `address`.
    pub source: RegisterNumber,
}

impl InstructionType for SingleDataSwap {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Self> {
        ((raw & 0x0FB0_0FF0) == 0x0100_0090).then_some(Self {
            condition,
            swap_byte: bit_is_set(raw, 22),
            address: select_bits(raw, 16, 4) as RegisterNumber,
            destination: select_bits(raw, 12, 4) as RegisterNumber,
            source: (raw & 0xF) as RegisterNumber,
        })
    }
}

impl fmt::Display for SingleDataSwap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let byte_suffix = if self.swap_byte { "b" } else { "" };
        write!(
            f,
            "swp{}{} r{},r{},[r{}]",
            self.condition, byte_suffix, self.destination, self.source, self.address
        )
    }
}

/// A software interrupt instruction (`swi`), which switches the CPU into
/// Supervisor mode and sets the program counter to the software interrupt
/// vector at address `8`.  This vector itself should be a branch instruction to
/// the actual interrupt handler.
#[derive(Debug, Eq, PartialEq)]
pub struct SoftwareInterrupt {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// A 24-bit comment included in the instruction that is completely ignored
    /// by the CPU.  This field can be used to pass data to the interrupt
    /// handler, which can access it via the following instruction sequence
    /// (note that the old program counter is stored in `r14_svc`):
    ///
    /// ```arm
    /// ldr r0, [r14, #-4]       ; Load SWI instruction into r0.
    /// bic r0, r0, #0xFF000000  ; Clear SWI bits, leaving only the comment.
    /// ```
    pub comment: u32,
}

impl InstructionType for SoftwareInterrupt {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Self> {
        let mask = 0x0F00_0000;
        ((raw & mask) == mask).then_some(Self {
            condition,
            // The comment comprises the entire instruction after the condition and SWI identifier.
            comment: raw & 0x00FF_FFFF,
        })
    }
}

impl fmt::Display for SoftwareInterrupt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "swi{} #{:#X}", self.condition, self.comment)
    }
}

/// A decoded instruction, converted from a `RawInstruction` by the decode unit.
/// Contains all information in the instruction required for execution in the
/// Execute stage.
#[derive(Display, Eq, PartialEq)]
pub enum Instruction {
    Branch(Branch),
    BranchAndExchange(BranchAndExchange),
    Multiply(Multiply),
    MultiplyLong(MultiplyLong),
    SingleDataSwap(SingleDataSwap),
    SoftwareInterrupt(SoftwareInterrupt),
}

/// Define the sequence in which instruction types should be decoded.  The
/// specified types are evaluated in sequence, with the first successful
/// decoding being returned.  The raw instruction and condition are the same for
/// all instructions.
macro_rules! decode_pipeline {
    ($raw:ident, $condition:ident => $first:ident, $($other:ident),+$(,)?) => {
        $first::decode($raw, $condition).map(Self::$first)
        $(
            .or_else(|| $other::decode($raw, $condition).map(Self::$other))
        )+
    }
}

impl Instruction {
    /// Decode the specified instruction, if it can be decoded.  If the
    /// instruction is not valid, `None` will be returned.
    pub fn decode(raw: RawInstruction) -> Option<Self> {
        let condition = Condition::from_u32(raw & 0xF000_0000)?;
        decode_pipeline!(
            raw, condition => Branch, Multiply, MultiplyLong, BranchAndExchange, SingleDataSwap, SoftwareInterrupt,
        )
    }
}

impl fmt::Debug for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
