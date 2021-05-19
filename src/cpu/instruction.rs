use crate::cpu::{AddressOffset, RegisterNumber};
use derive_more::Display;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use std::fmt;

/// Determine whether the bit at the specified `index`, counted from the least
/// significant bit, is set in the specified `value`.
const fn bit_is_set(value: u32, index: u8) -> bool {
    value & (1 << index) != 0
}

/// Select the specified number of bits (`size`) beginning at the specified
/// `low_bit` index in the specified `value`.  The resulting value will feature
/// the low bit shifted into index `0`.
const fn select_bits(value: u32, low_bit: u8, size: u8) -> u32 {
    (value >> low_bit) & ((1 << size) - 1)
}

/// Extend the value of the bit in the specified `sign_bit` of the specified
/// `value` through all bits above the sign bit.
const fn sign_extend(value: u32, sign_bit: u8) -> i32 {
    let shift = 31 - sign_bit;
    ((value as i32) << shift) >> shift
}

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
    Equal,
    /// Values are not equal (`Z` flag clear, suffix `ne`).
    NotEqual,
    /// Unsigned greater than or equal (`C` flag set, suffix `cs`).
    HigherOrSame,
    /// Unsigned less than (`C` flag clear, suffix `cc`).
    Lower,
    /// Value is negative (`N` flag set, suffix `mi`).
    Negative,
    /// Value is non-negative (`N` flag clear, suffix `pl`).
    NonNegative,
    /// Signed operation overflowed (`V` flag set, suffix `vs`).
    Overflow,
    /// Signed operation did not overflow (`V` flag clear, suffix `vc`).
    NoOverflow,
    /// Unsigned greater than (`C` set and `Z` clear, suffix `hi`).
    Higher,
    /// Unsigned less than or equal (`C` clear or `Z` set, suffix `ls`).
    LowerOrSame,
    /// Signed greater than or equal (`N == V`, suffix `ge`).
    GreaterOrEqual,
    /// Signed less than (`N != V`, suffix `lt`).
    Less,
    /// Signed greater than (`Z` flag clear and `N == V`, suffix `gt`).
    Greater,
    /// Signed less than or equal (`Z` flag set or `N != V`, suffix `le`).
    LessOrEqual,
    /// Execute unconditionally (suffix `al`).
    Always,
}

/// The operations permissible in the `OpCode` field of an arithmetic (data
/// processing) instruction.
#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum ArithmeticOperation {
    /// `Rd := Op1 AND Op2`; mnemonic `and`.
    And,
    /// `Rd := Op1 XOR Op2`; mnemonic `eor`.
    ExclusiveOr,
    /// `Rd := Op1 - Op2`; mnemonic `sub`.
    Subtract,
    /// `Rd := Op2 - Op1`; mnemonic `rsb`.
    ReverseSubtract,
    /// `Rd := Op1 + Op2`; mnemonic `add`.
    Add,
    /// `Rd := Op1 + Op2 + C`; mnemonic `adc`.
    AddWithCarry,
    /// `Rd := Op1 - Op2 + C - 1`; mnemonic `sbc`.
    SubtractWithCarry,
    /// `Rd := Op2 - Op1 + C - 1`; mnemonic `rsc`.
    ReverseSubtractWithCarry,
    /// Set condition codes on `Op1 AND Op2`; mnemonic `tst`.
    Test,
    /// Set condition codes on `Op1 XOR Op2`; mnemonic `teq`.
    TestEqual,
    /// Set condition codes on `Op1 - Op2`; mnemonic `cmp`.
    CompareSubtract,
    /// Set condition codes on `Op1 + Op2`; mnemonic `cmn`.
    CompareAdd,
    /// `Rd := Op1 OR Op2`; mnemonic `orr`.
    InclusiveOr,
    /// `Rd := Op2`; mnemonic `mov`.
    Move,
    /// `Rd := Op1 AND NOT Op2`; mnemonic `bic`.
    BitClear,
    /// `Rd := NOT Op2`; mnemonic `mvn`.
    MoveInverse,
}

/// The types of register value manipulation that can be performed in a
/// register-shift operand for data processing instructions.
#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum ShiftType {
    /// Perform a logical left shift, shifting the value of the register to the
    /// left by the specified number of bits without sign extension and
    /// discarding any bits that are shifted out from the resultant value.  The
    /// carry flag is set to the value of the least significant bit that was
    /// shifted out for *logical* operations only; if the shift amount is `0`,
    /// this flag is not modified.  Mnemonic: `lsl`.
    LogicalShiftLeft,
    /// Perform a logical right shift, shifting the value of the register to the
    /// right by the specified number of bits without sign extension and
    /// discarding any bits that are shifted out from the resultant value.  If
    /// the shift amount is `0`, then the actual shift performed is 32 bits,
    /// resulting in the entire value of the register being shifted out.  For
    /// *logical* operations, the carry flag is set to the most significant bit
    /// that was shifted out.  Mnemonic: `lsr`.
    LogicalShiftRight,
    /// Perform an arithmetic right shift, which is identical to the logical
    /// right shift except the most significant bit of the source register's
    /// value will be extended through all the most significant values shifted
    /// in.  This behaviour approximates two's complement division by a power of
    /// 2 for both signed and unsigned values.  Mnemonic: `asr`.
    ArithmeticShiftRight,
    /// Perform a rightward rotation, in which the value of the register is
    /// shifted to the right by the specified amount and the values carried out
    /// are wrapped around to the most significant bits of the resultant value.
    /// The mnemonic for this form of the instruction is `ror`.  If the amount
    /// by which to rotate is `0`, then the value is shifted to the right by 1
    /// bit and the carry flag is carried into the most significant bit; the
    /// mnemonic for this form of the shift is `rrx` and is only used when
    /// shifting by an immediate `#0`.  The carry flag is modified as in the
    /// other shift types.
    RotateRight,
}

/// The complex operand in a data-processing operation, which may consist of
/// either the barrel shifter-modified value of a register or a limited subset
/// of immediate values that can be specified as a value rotated rightward by a
/// multiple of 2.
#[derive(Debug, Eq, PartialEq)]
pub enum DataOperand {
    /// The operand is an immediate value.  The encoding of these values is
    /// extremely idiosyncratic, consisting of an 8-bit unsigned value that can
    /// be right-rotated by a 4-bit field, which is itself implicitly multiplied
    /// by 2.  The rotation logic itself is performed by the decoder.
    Immediate(u32),
    /// The operand is a register value (2) shifted by an immediate amount (1).
    ShiftImmediate(ShiftType, u8, RegisterNumber),
    /// The operand is a register value (2) shifted by the value stored in the
    /// low byte of another register (1).  Note that the exceptions documented
    /// for shift values of `0` do not apply when a register is used as the
    /// shift operand: instead, shifting by a register value `0` is a no-op.
    ShiftRegister(ShiftType, RegisterNumber, RegisterNumber),
}

impl DataOperand {
    /// Decode an immediate data operand in the low 12 bits of the specified
    /// `spec`ification, as described for the `Immediate` variant.
    pub fn decode_immediate(spec: u32) -> Self {
        let value = spec & 0xFF;
        let rotation = select_bits(spec, 8, 4) * 2;
        Self::Immediate(value.rotate_right(rotation))
    }

    /// Decode a register data operand in the low 12 bits of the specified
    /// `spec`ification, as described for the `ShiftImmediate` and
    /// `ShiftRegister` variants.
    ///
    /// # Panics
    /// May panic if the number of variants of `ShiftType` is reduced; however,
    /// this panic should not occur provided that the 4 variants defined by the
    /// ARM documentation are retained.
    pub fn decode_register(spec: u32) -> Self {
        let source_register = (spec & 0xF) as RegisterNumber;
        let shift_type = ShiftType::from_u32(select_bits(spec, 5, 2)).unwrap();

        if bit_is_set(spec, 4) {
            // If bit 4 is set, the shift amount is stored in a register.
            let shift_register = select_bits(spec, 8, 4) as RegisterNumber;
            Self::ShiftRegister(shift_type, shift_register, source_register)
        } else {
            // Shift amount is an immediate value.
            let shift_amount = select_bits(spec, 7, 5) as u8;
            Self::ShiftImmediate(shift_type, shift_amount, source_register)
        }
    }
}

/// A specific type of ARM instruction with a unique encoding scheme.
pub trait InstructionType: fmt::Display + Sized {
    /// Decode the specified instruction to be executed only upon the specified
    /// condition, returning a variant of the decoded `Instruction` type.
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction;
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
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction {
        Instruction::Branch(Self {
            condition,
            // If bit 24 is set, this is a Branch with Link (bl).
            link: bit_is_set(raw, 24),
            // 24-bit offset must be shifted 2 bits to the right.
            offset: sign_extend(raw << 2, 25),
        })
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
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction {
        Instruction::BranchAndExchange(Self {
            condition,
            // The register number is encoded in the low nybble of the instruction.
            source: (raw & 0xF) as RegisterNumber,
        })
    }
}

/// A data processing operation, comprising most ARM instructions that utilise
/// the ALU.
#[derive(Debug, Eq, PartialEq)]
pub struct DataProcessing {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// The operation to be performed by the ALU for this instruction.
    pub operation: ArithmeticOperation,
    /// Whether the condition codes in the CPSR should be affected as a result
    /// of this operation.
    pub set_cpsr: bool,
    /// The register whose value will be used as the first operand of this
    /// instruction if the `operation` requires two operands.
    pub operand1: RegisterNumber,
    /// The register in which the result of this operation will be stored.
    pub destination: RegisterNumber,
    /// The operand that is always used in this instruction.  Decoded from the
    /// low bits of the machine code as either an immediate value or a shifted
    /// register value dependent upon the value of bit 25 (`I`).
    pub operand2: DataOperand,
}

impl InstructionType for DataProcessing {
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction {
        Instruction::DataProcessing(Self {
            condition,
            operation: ArithmeticOperation::from_u32(select_bits(raw, 21, 4)).unwrap(),
            set_cpsr: bit_is_set(raw, 20),
            operand1: select_bits(raw, 16, 4) as RegisterNumber,
            destination: select_bits(raw, 12, 4) as RegisterNumber,
            operand2: if bit_is_set(raw, 25) {
                DataOperand::decode_immediate(raw)
            } else {
                DataOperand::decode_register(raw)
            },
        })
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
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction {
        Instruction::Multiply(Self {
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
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction {
        Instruction::MultiplyLong(Self {
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

/// A specialised operation to transfer the value stored in either CPSR or the
/// current mode's SPSR to a register.  This instruction corresponds to the
/// mnemonic `mrs`.
#[derive(Debug, Eq, PartialEq)]
pub struct PsrRegisterTransfer {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// Whether to transfer the CPSR (`false`) or current mode's SPSR (`true`)
    /// to the destination register.
    pub use_spsr: bool,
    /// The register into which to transfer the specified PSR.
    pub destination: RegisterNumber,
}

impl InstructionType for PsrRegisterTransfer {
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction {
        // This instruction type overlaps with data processing in non-tabled bits.
        if (raw & 0x0FBF_0FFF) == 0x010F_0000 {
            Instruction::PsrRegisterTransfer(Self {
                condition,
                use_spsr: bit_is_set(raw, 22),
                destination: select_bits(raw, 12, 4) as RegisterNumber,
            })
        } else {
            DataProcessing::decode(raw, condition)
        }
    }
}

/// A specialised operation to transfer the value stored in a register to either
/// the CPSR or the current mode's SPSR.  Either the entire register or only the
/// flag bits can be transferred; in User mode, both variants perform the same
/// operation since only the flags are writable in that mode.  This instruction
/// corresponds to the mnemonic `msr`.
#[derive(Debug, Eq, PartialEq)]
pub struct RegisterPsrTransfer {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// Whether to transfer the source value to the CPSR (`false`) or the
    /// current mode's SPSR (`true`).
    pub use_spsr: bool,
    /// Whether to transfer the value to the entirety of the PSR (`false`) or
    /// only the flag bits (`true`).
    pub flags_only: bool,
    /// The location from which the new PSR value should be sourced.  When
    /// transferring to the entire PSR, this may only be a register; when
    /// transferring only the flag bits, it may be either a register or an
    /// immediate value.
    pub source: DataOperand,
}

impl InstructionType for RegisterPsrTransfer {
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction {
        // This instruction type overlaps with data processing in non-tabled bits.
        if (raw & 0x0FBF_FFF0) == 0x0129_F000 || (raw & 0x0DBF_F000) == 0x0128_F000 {
            let use_spsr = bit_is_set(raw, 22);
            Instruction::RegisterPsrTransfer(if bit_is_set(raw, 16) {
                // Bit 16 indicates that the entire PSR should be transferred.
                Self {
                    condition,
                    use_spsr,
                    flags_only: false,
                    source: DataOperand::ShiftImmediate(
                        ShiftType::LogicalShiftLeft,
                        0,
                        (raw & 0xF) as RegisterNumber,
                    ),
                }
            } else {
                Self {
                    condition,
                    use_spsr,
                    flags_only: true,
                    source: if bit_is_set(raw, 25) {
                        DataOperand::decode_immediate(raw)
                    } else {
                        DataOperand::decode_register(raw)
                    },
                }
            })
        } else {
            DataProcessing::decode(raw, condition)
        }
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
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction {
        Instruction::SingleDataSwap(Self {
            condition,
            swap_byte: bit_is_set(raw, 22),
            address: select_bits(raw, 16, 4) as RegisterNumber,
            destination: select_bits(raw, 12, 4) as RegisterNumber,
            source: (raw & 0xF) as RegisterNumber,
        })
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
    fn decode(raw: RawInstruction, condition: Condition) -> Instruction {
        Instruction::SoftwareInterrupt(Self {
            condition,
            // The comment comprises the entire instruction after the condition and SWI identifier.
            comment: raw & 0x00FF_FFFF,
        })
    }
}

/// A decoded instruction, converted from a `RawInstruction` by the decode unit.
/// Contains all information in the instruction required for execution in the
/// Execute stage.
#[derive(Display, Eq, PartialEq)]
pub enum Instruction {
    Branch(Branch),
    BranchAndExchange(BranchAndExchange),
    DataProcessing(DataProcessing),
    Multiply(Multiply),
    MultiplyLong(MultiplyLong),
    PsrRegisterTransfer(PsrRegisterTransfer),
    RegisterPsrTransfer(RegisterPsrTransfer),
    SingleDataSwap(SingleDataSwap),
    SoftwareInterrupt(SoftwareInterrupt),
}

// Include the decode lookup tables generated at build time.
include!(concat!(env!("OUT_DIR"), "/codegen_decode_tables.rs"));

impl Instruction {
    /// Decode the specified instruction, if it can be decoded.  If the
    /// instruction is not valid, `None` will be returned.
    pub fn decode(raw: RawInstruction) -> Option<Self> {
        let condition = Condition::from_u32(raw >> 28)?;
        // Look up this instruction in the instruction type tables.
        let l1_index = select_bits(raw, 20, 8) as usize;
        let l2_offset = select_bits(raw, 4, 4) as usize;
        Some(DECODE_L2_TABLE[DECODE_L1_TABLE[l1_index] + l2_offset](
            raw, condition,
        ))
    }
}
