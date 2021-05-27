use crate::{
    bit_twiddling::BitTwiddling,
    cpu::{AddressOffset, CoprocessorRegister, RegisterNumber},
};
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

/// "Decode" an instruction that falls into a documented gap in the encoding
/// space.  Note that this function should *not* be used to return any invalid
/// instruction, only those that are explicitly designated to be undefined by
/// the ISA.
const fn decode_undefined(_raw: RawInstruction, _condition: Condition) -> Option<Instruction> {
    None
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
    #[must_use]
    fn decode_immediate(spec: RawInstruction) -> Self {
        let value = spec & 0xFF;
        let rotation = spec.select_bits(8, 4) * 2;
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
    #[must_use]
    fn decode_register(spec: RawInstruction) -> Self {
        let source_register = RegisterNumber::extract(spec, 0);
        let shift_type = ShiftType::from_u32(spec.select_bits(5, 2)).unwrap();

        if spec.bit_is_set(4) {
            // If bit 4 is set, the shift amount is stored in a register.
            let shift_register = RegisterNumber::extract(spec, 8);
            Self::ShiftRegister(shift_type, shift_register, source_register)
        } else {
            // Shift amount is an immediate value.
            let shift_amount = spec.select_bits(7, 5) as u8;
            Self::ShiftImmediate(shift_type, shift_amount, source_register)
        }
    }
}

/// A collection of instruction fields that are common to all data transfer
/// instructions.  These fields control the addressing mode and type of
/// operation performed for each instruction.
#[derive(Debug, Eq, PartialEq)]
pub struct DataTransferOptions {
    /// Whether the offset should be added to the base address before
    /// (pre-indexing, `true`) or after (post-indexing, `false`) the memory
    /// transfer is performed.
    pub pre_index: bool,
    /// Whether the offset should be added to (`true`) or subtracted from
    /// (`false`) the value of the base register.
    pub add_offset: bool,
    /// Whether the computed address should be written back to the base address
    /// register once the memory transfer is complete.  For post-indexed
    /// addresses, this value should only be `true` if the CPU is running in a
    /// privileged mode; in this environment, setting the write-back bit high
    /// will result in the transfer being performed in User mode.  Since the GBA
    /// does not feature memory protection or address translation, this
    /// mode-switching functionality is irrelevant to us.
    pub write_back: bool,
    /// Whether we should read a value from memory (load, `true`) or write a
    /// value out to memory (store, `false`).
    pub load: bool,
    /// The register from which to source the base address before the offset is
    /// applied.  If write-back is requested, this register will contain the
    /// offset address after the memory operation is performed.
    pub base: RegisterNumber,
}

impl DataTransferOptions {
    /// Decode the common components of a data transfer operation.  No
    /// error checking is performed upon these values, so it is the
    /// responsibility of the caller to handle all validation.
    fn decode(spec: RawInstruction) -> Self {
        Self {
            pre_index: spec.bit_is_set(24),
            add_offset: spec.bit_is_set(23),
            write_back: spec.bit_is_set(21),
            load: spec.bit_is_set(20),
            base: RegisterNumber::extract(spec, 16),
        }
    }
}

/// Special mode-switching operations that may be performed by
/// `BlockDataTransfer` instructions in addition to the straightforward register
/// transfer.  Nearly all instructions will likely use the `Normal` variant: the
/// others are only permissible in privileged modes.
#[derive(Debug, Eq, PartialEq)]
pub enum BlockTransferMode {
    /// The registers should be transferred from the current mode's bank as
    /// specified, and no modifications should be performed to CPSR.
    Normal,
    /// The SPSR for the current mode should be transferred to CPSR.  This
    /// option should only be specified when the instruction is a load (`ldm`),
    /// the `S` bit in the instruction is set, and `r15` (`pc`) is present in
    /// the list of registers to be transferred.
    LoadSpsr,
    /// The registers should be transferred from the User bank rather than the
    /// current mode's bank.  This option should only be specified when the `S`
    /// bit in the instruction is set and the rules for `LoadSpsr` do not apply.
    UserBank,
}

/// The amount of data and byte order to be transferred in a single data
/// transfer instruction.
#[derive(Debug, Eq, PartialEq)]
pub enum SingleTransferType {
    /// Transfer a zero-extended 8-bit value.
    UnsignedByte,
    /// Transfer a sign-extended 8-bit value.
    SignedByte,
    /// Transfer a zero-extended 16-bit value.
    UnsignedHalfWord,
    /// Transfer a sign-extended 16-bit value.
    SignedHalfWord,
    /// Transfer a 32-bit value.
    Word,
}

/// A collection of instruction fields that are common to multiple types of
/// coprocessor operations.  These fields are passed directly to the coprocessor
/// and are not interpreted by the CPU past the decode stage.
#[derive(Debug, Eq, PartialEq)]
pub struct CoprocessorOptions {
    /// An opcode (field `CP Opc`) specifying the specific operation to be
    /// performed by the coprocessor.
    pub operation: u8,
    /// The coprocessor register `CRn` to be used as the first operand in the
    /// requested coprocessor operation.
    pub operand1: CoprocessorRegister,
    /// The index of the coprocessor on which the operation should be executed.
    /// All coprocessors other than that specified will ignore this instruction.
    pub coprocessor: u8,
    /// The field `CP` ("Coprocessor information"), which encodes some
    /// additional information that may be considered in conjunction with
    /// `CP Opc` to determine the operation to be performed.
    pub info: u8,
    /// The coprocessor register `CRm` to be used as the second operand in the
    /// requested coprocessor operation.
    pub operand2: CoprocessorRegister,
}

impl CoprocessorOptions {
    /// Decode the common components of a coprocessor operation with the
    /// specified `opcode`; the instruction must have already been validated as
    /// a coprocessor operation for this function to generate sensible values.
    fn decode(spec: RawInstruction, opcode: u8) -> Self {
        Self {
            operation: opcode,
            operand1: CoprocessorRegister::extract(spec, 16),
            coprocessor: spec.select_bits(8, 4) as u8,
            info: spec.select_bits(5, 3) as u8,
            operand2: CoprocessorRegister::extract(spec, 0),
        }
    }
}

/// A specific type of ARM instruction with a unique encoding scheme.
pub trait InstructionType: fmt::Display + Sized {
    /// Decode the specified instruction to be executed only upon the specified
    /// condition, returning a variant of the decoded `Instruction` type.  If
    /// the instruction could not be decoded, `None` is returned.
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction>;
}

/// A block data transfer operation, which loads or stores multiple registers
/// from or to memory at a time.  The control bits `P` and `U` define four
/// addressing modes for these instructions: pre- and post- increment and
/// decrement, each of which determines whether the registers are written above
/// or below the base address and the value of the base register if write-back
/// is requested.
#[derive(Debug, Eq, PartialEq)]
pub struct BlockDataTransfer {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// The mode-switching operation that should occur when this instruction is
    /// executed; this field is derived from multiple bits in the instruction.
    pub mode: BlockTransferMode,
    /// Options set for this instruction that are common to all memory transfer
    /// operations.
    pub opt: DataTransferOptions,
    /// A list of the registers to be transferred, in which the bit at each
    /// index, counted from the least significant, indicates whether that bit
    /// should be transferred.
    pub registers: u16,
}

impl InstructionType for BlockDataTransfer {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        let transfer_r15 = raw.bit_is_set(15);
        let user_psr_bit = raw.bit_is_set(22);
        let opt = DataTransferOptions::decode(raw);

        Some(Instruction::BlockDataTransfer(Self {
            condition,
            mode: if opt.load && transfer_r15 && user_psr_bit {
                BlockTransferMode::LoadSpsr
            } else if user_psr_bit {
                BlockTransferMode::UserBank
            } else {
                BlockTransferMode::Normal
            },
            opt,
            registers: raw as u16,
        }))
    }
}

/// A branch instruction, which sets the program counter to an address offset
/// from its current value as specified in the instruction.
#[derive(Debug, Eq, PartialEq)]
pub struct Branch {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// Whether the current value of the program counter should be stored in
    /// `r14` (the *link* register `lr`) when this instruction is executed.
    pub link: bool,
    /// The offset from the current program counter to which to branch.  Due to
    /// instruction prefetch, the target address will be 8 bytes beyond that of
    /// the instruction itself; since the pipeline is simulated by `rgba`, this
    /// concern is ignored.
    pub offset: AddressOffset,
}

impl InstructionType for Branch {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        Some(Instruction::Branch(Self {
            condition,
            // If bit 24 is set, this is a Branch with Link (bl).
            link: raw.bit_is_set(24),
            // 24-bit offset must be shifted 2 bits to the right.
            offset: (raw << 2).sign_extend(25),
        }))
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
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        Some(Instruction::BranchAndExchange(Self {
            condition,
            // The register number is encoded in the low nybble of the instruction.
            source: RegisterNumber::extract(raw, 0),
        }))
    }
}

/// An operation performed internally within a coprocessor; as such, these
/// instructions do not reference any CPU state other than the CPSR in order to
/// determine whether the instruction should be dispatched.
#[derive(Debug, Eq, PartialEq)]
pub struct CoprocessorDataOperation {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// Options set for this instruction that are common to multiple coprocessor
    /// operation types.
    pub opt: CoprocessorOptions,
    /// The coprocessor register in which the result of the requested operation
    /// should be stored by convention.
    pub destination: CoprocessorRegister,
}

impl InstructionType for CoprocessorDataOperation {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        // These operations use a complete 4-bit primary opcode.
        let opcode = raw.select_bits(20, 4) as u8;

        Some(Instruction::CoprocessorDataOperation(Self {
            condition,
            opt: CoprocessorOptions::decode(raw, opcode),
            destination: CoprocessorRegister::extract(raw, 12),
        }))
    }
}

/// A load or store of data between memory and a coprocessor's registers.  The
/// exact amount of memory to be transferred is controlled by the coprocessor,
/// which is passed a limited amount of instruction data by the CPU.
#[derive(Debug, Eq, PartialEq)]
pub struct CoprocessorDataTransfer {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// The value of the `N` bit, which is intended for use by coprocessors to
    /// determine the amount of memory to be transferred.  Regardless of its
    /// use, this field is not interpreted by the CPU.
    pub transfer_length: bool,
    /// Options set for this instruction that are common to all memory transfer
    /// operations.
    pub opt: DataTransferOptions,
    /// The coprocessor register `CRd` that serves as either the destination
    /// (load) or source (store) of the data transfer.
    pub target: CoprocessorRegister,
    /// The number of the coprocessor targeted by this operation.  Only the
    /// coprocessor with the specified index should respond to this instruction.
    pub coprocessor: u8,
    /// The offset to be added to or subtracted from the value of the base
    /// register to obtain the memory address at which this operation should
    /// occur.  For this instruction, the offset will always be `Immediate` and
    /// its value will be shifted left by 2 bits during decoding.
    pub offset: DataOperand,
}

impl InstructionType for CoprocessorDataTransfer {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        Some(Instruction::CoprocessorDataTransfer(Self {
            condition,
            transfer_length: raw.bit_is_set(22),
            opt: DataTransferOptions::decode(raw),
            target: CoprocessorRegister::extract(raw, 12),
            coprocessor: raw.select_bits(8, 4) as u8,
            offset: DataOperand::Immediate((raw & 0xFF) << 2),
        }))
    }
}

/// A direct transfer between a coprocessor register and a CPU register, which
/// may include the flag bits in the CPSR.
#[derive(Debug, Eq, PartialEq)]
pub struct CoprocessorRegisterTransfer {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// Options set for this instruction that are common to multiple coprocessor
    /// operation types.
    pub opt: CoprocessorOptions,
    /// Whether this operation is a load from a coprocessor to the CPU (`true`,
    /// mnemonic `mrc`) or a store from the CPU to a coprocessor (`false`,
    /// mnemonic `mcr`).
    pub load: bool,
    /// Either the register from which to source the value to write for a store
    /// or into which to read the value of a load, depending on the type of
    /// operation being performed.  If this register is `r15` (`pc`) and the
    /// specified operation is a load, then the flags of the CPSR (`cpsr_flg`)
    /// are transferred and all other bits, as well as the program counter, are
    /// unaffected; stores simply transfer the value of `r15`, plus a pipeline
    /// offset of 12.
    pub target: RegisterNumber,
}

impl InstructionType for CoprocessorRegisterTransfer {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        // These operations use only a 3-bit primary opcode.
        let opcode = raw.select_bits(21, 3) as u8;

        Some(Instruction::CoprocessorRegisterTransfer(Self {
            condition,
            opt: CoprocessorOptions::decode(raw, opcode),
            load: raw.bit_is_set(20),
            target: RegisterNumber::extract(raw, 12),
        }))
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
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        Some(Instruction::DataProcessing(Self {
            condition,
            operation: ArithmeticOperation::from_u32(raw.select_bits(21, 4))?,
            set_cpsr: raw.bit_is_set(20),
            operand1: RegisterNumber::extract(raw, 16),
            destination: RegisterNumber::extract(raw, 12),
            operand2: if raw.bit_is_set(25) {
                DataOperand::decode_immediate(raw)
            } else {
                DataOperand::decode_register(raw)
            },
        }))
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
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        Some(Instruction::Multiply(Self {
            condition,
            accumulate: raw.bit_is_set(21),
            set_cpsr: raw.bit_is_set(20),
            destination: RegisterNumber::extract(raw, 16),
            addend: RegisterNumber::extract(raw, 12),
            multiplicand1: RegisterNumber::extract(raw, 8),
            multiplicand2: RegisterNumber::extract(raw, 0),
        }))
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
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        Some(Instruction::MultiplyLong(Self {
            condition,
            signed: raw.bit_is_set(22),
            accumulate: raw.bit_is_set(21),
            set_cpsr: raw.bit_is_set(20),
            destination_high: RegisterNumber::extract(raw, 16),
            destination_low: RegisterNumber::extract(raw, 12),
            multiplicand1: RegisterNumber::extract(raw, 8),
            multiplicand2: RegisterNumber::extract(raw, 0),
        }))
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
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        // This instruction type overlaps with data processing in non-tabled bits.
        ((raw & 0x0FBF_0FFF) == 0x010F_0000)
            .then_some(Instruction::PsrRegisterTransfer(Self {
                condition,
                use_spsr: raw.bit_is_set(22),
                destination: RegisterNumber::extract(raw, 12),
            }))
            .or_else(|| DataProcessing::decode(raw, condition))
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
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        let use_spsr = raw.bit_is_set(22);

        // This instruction type overlaps with data processing in non-tabled bits.
        ((raw & 0x0FBF_FFF0) == 0x0129_F000 || (raw & 0x0DBF_F000) == 0x0128_F000)
            .then_some(Instruction::RegisterPsrTransfer(if raw.bit_is_set(16) {
                // Bit 16 indicates that the entire PSR should be transferred.
                Self {
                    condition,
                    use_spsr,
                    flags_only: false,
                    source: DataOperand::ShiftImmediate(
                        ShiftType::LogicalShiftLeft,
                        0,
                        RegisterNumber::extract(raw, 0),
                    ),
                }
            } else {
                Self {
                    condition,
                    use_spsr,
                    flags_only: true,
                    source: if raw.bit_is_set(25) {
                        DataOperand::decode_immediate(raw)
                    } else {
                        DataOperand::decode_register(raw)
                    },
                }
            }))
            .or_else(|| DataProcessing::decode(raw, condition))
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
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        Some(Instruction::SingleDataSwap(Self {
            condition,
            swap_byte: raw.bit_is_set(22),
            address: RegisterNumber::extract(raw, 16),
            destination: RegisterNumber::extract(raw, 12),
            source: RegisterNumber::extract(raw, 0),
        }))
    }
}

/// A load or store of either a single byte or an entire word between a register
/// and a memory address specified from a base register, plus or minus an
/// offset stored either as an immediate value or in memory.  This instruction
/// may use either pre- or post-increment logic for the addition of this offset,
/// and the resultant address may optionally be written back to the base
/// register.
#[derive(Debug, Eq, PartialEq)]
pub struct SingleDataTransfer {
    /// The condition upon which this instruction will be executed.
    pub condition: Condition,
    /// The amount of memory to transfer, and the most significant bit extension
    /// to apply to the transferred quantity.
    pub transfer_type: SingleTransferType,
    /// Options set for this instruction that are common to all memory transfer
    /// operations.
    pub opt: DataTransferOptions,
    /// Either the register from which to source the value to write for a store
    /// or into which to read the value of a load, depending on the type of
    /// operation being performed.
    pub target: RegisterNumber,
    /// The offset to apply to the base address in the manner specified
    /// elsewhere in the instruction.  Note that while the register-relative
    /// forms are the same as in the `DataProcessing` instructions, the
    /// immediate variant is a directly-encoded 12-bit value, lacking the
    /// rotation field.
    pub offset: DataOperand,
}

impl InstructionType for SingleDataTransfer {
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        Some(Instruction::SingleDataTransfer(Self {
            condition,
            transfer_type: if raw.bit_is_set(22) {
                SingleTransferType::UnsignedByte
            } else {
                SingleTransferType::Word
            },
            opt: DataTransferOptions::decode(raw),
            target: RegisterNumber::extract(raw, 12),
            offset: if raw.bit_is_set(25) {
                // Only immediate shifts are supported by this instruction.
                let offset = DataOperand::decode_register(raw);
                matches!(offset, DataOperand::ShiftImmediate(_, _, _)).then_some(offset)?
            } else {
                DataOperand::Immediate(raw & 0xFFF)
            },
        }))
    }
}

impl SingleDataTransfer {
    /// Decode an instruction transferring a single value between a register and
    /// memory using the alternate encoding scheme, which is called the
    /// *Halfword and Signed Data Transfer* scheme in the ARM documentation.
    /// Note especially that this encoding scheme is **less** specific than
    /// those that precede it, and so it must immediately follow the
    /// `DataProcessing` instructions in the decoding priority table.
    #[must_use]
    pub fn decode_alternate(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        let transfer_type = match (raw.bit_is_set(6), raw.bit_is_set(5)) {
            (true, true) => SingleTransferType::SignedHalfWord,
            (true, false) => SingleTransferType::SignedByte,
            (false, true) => SingleTransferType::UnsignedHalfWord,
            _ => unreachable!("Instruction decode sequencing failure"),
        };

        Some(Instruction::SingleDataTransfer(Self {
            condition,
            transfer_type,
            opt: DataTransferOptions::decode(raw),
            target: RegisterNumber::extract(raw, 12),
            offset: if raw.bit_is_set(22) {
                // Offset is an 8-bit immediate divided by the S and H bits.
                DataOperand::Immediate(((raw >> 4) & 0xF0) | (raw & 0xF))
            } else {
                // Offset is a register with no scaling.
                DataOperand::ShiftImmediate(ShiftType::LogicalShiftLeft, 0, RegisterNumber::extract(raw, 0))
            },
        }))
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
    fn decode(raw: RawInstruction, condition: Condition) -> Option<Instruction> {
        Some(Instruction::SoftwareInterrupt(Self {
            condition,
            // The comment comprises the entire instruction after the condition and SWI identifier.
            comment: raw & 0x00FF_FFFF,
        }))
    }
}

/// A decoded instruction, converted from a `RawInstruction` by the decode unit.
/// Contains all information in the instruction required for execution in the
/// Execute stage.
#[derive(Display, Eq, PartialEq)]
pub enum Instruction {
    BlockDataTransfer(BlockDataTransfer),
    Branch(Branch),
    BranchAndExchange(BranchAndExchange),
    CoprocessorDataOperation(CoprocessorDataOperation),
    CoprocessorDataTransfer(CoprocessorDataTransfer),
    CoprocessorRegisterTransfer(CoprocessorRegisterTransfer),
    DataProcessing(DataProcessing),
    Multiply(Multiply),
    MultiplyLong(MultiplyLong),
    PsrRegisterTransfer(PsrRegisterTransfer),
    RegisterPsrTransfer(RegisterPsrTransfer),
    SingleDataSwap(SingleDataSwap),
    SingleDataTransfer(SingleDataTransfer),
    SoftwareInterrupt(SoftwareInterrupt),
}

// Include the decode lookup tables generated at build time.
include!(concat!(env!("OUT_DIR"), "/codegen_decode_tables.rs"));

impl Instruction {
    /// Decode the specified instruction, if it can be decoded.  If the
    /// instruction is not valid, `None` will be returned.
    #[must_use]
    pub fn decode(raw: RawInstruction) -> Option<Self> {
        let condition = Condition::from_u32(raw >> 28)?;
        // Look up this instruction in the instruction type tables.
        let l1_index = raw.select_bits(20, 8) as usize;
        let l2_offset = raw.select_bits(4, 4) as usize;
        DECODE_L2_TABLE[DECODE_L1_TABLE[l1_index] + l2_offset](raw, condition)
    }
}
