use crate::bit_twiddling::BitTwiddling;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use std::{
    convert::TryFrom,
    ops::{Index, IndexMut},
};

pub mod disassembly;
pub mod instruction;

/// A memory address, denoting a pointer into the system's memory.
pub type Address = u32;

/// An offset from an `Address`, equivalent to a `ptrdiff_t`.
pub type AddressOffset = i32;

/// A coprocessor register number, nominally restricted to the range `[0, 15]`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CoprocessorRegister(pub u8);

impl CoprocessorRegister {
    /// Extract a coprocessor register number beginning at the specified
    /// `low_bit` index in the specified `instruction`.
    #[must_use]
    pub fn extract(instruction: u32, low_bit: u8) -> Self {
        Self(instruction.select_bits(low_bit, 4) as u8)
    }
}

/// A register number, nominally restricted to the range `[0, 15]`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RegisterNumber(pub u8);

impl RegisterNumber {
    /// Extract a register number beginning at the specified `low_bit` index in
    /// the specified `instruction`.
    #[must_use]
    pub fn extract(instruction: u32, low_bit: u8) -> Self {
        Self(instruction.select_bits(low_bit, 4) as u8)
    }
}

/// The operating mode of the ARM7TDMI CPU.  All modes other than `User` are
/// privileged and thus can execute privileged instructions.
#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum Mode {
    /// The standard mode of execution; this mode is unprivileged.
    User = 16,
    /// A higher-priority interrupt mode (FIQ) that can preëmpt IRQ handlers.
    FastInterrupt = 17,
    /// The mode in which general purpose interrupt (IRQ) handlers are executed.
    Interrupt = 18,
    /// A privileged mode entered as the result of a software interrupt (`swi`).
    Supervisor = 19,
    /// A mode entered after a data or instruction prefetch abort.
    Abort = 23,
    /// A mode entered when an illegal instruction is encountered.
    Undefined = 27,
    /// A privileged mode entered by setting the mode bit in the CPSR; the only
    /// privileged mode that can be entered without an interrupt.
    System = 31,
}

/// An expanded representation of a Program Status Register (PSR) of the
/// ARM7TDMI CPU.  Since individual fields of the PSRs are accessed
/// substantially more frequently than the registers as a whole, the program
/// status is not stored as a bit-field as documented, but can be synthesised
/// to a 32-bit register if necessary.
pub struct StatusRegister {
    /// The current operating mode of the CPU; bits `M0`&ndash;`M4` of the PSR.
    pub mode: Mode,
    /// Whether the system is in Thumb (`true`) or ARM (`false`) mode; bit `T`
    /// of the PSR.
    pub thumb: bool,
    /// Whether `FastInterrupt` (FIQ) requests should be disabled (`true`) or
    /// enabled (`false`); bit `F` of the PSR.
    pub fiq_disable: bool,
    /// Whether regular `Interrupt` (IRQ) requests should be disabled (`true`)
    /// or enabled (`false`); bit `I` of the PSR.
    pub irq_disable: bool,
    /// The overflow flag `V`, indicating a signed integer overflow.
    pub flag_overflow: bool,
    /// The carry flag `C`, indicating an unsigned integer overflow.
    pub flag_carry: bool,
    /// The zero flag `Z`, indicating that the result of an operation was `0`.
    pub flag_zero: bool,
    /// The negative flag `N`, indicating that the result of an operation was
    /// negative (most significant bit set).
    pub flag_negative: bool,
}

impl From<StatusRegister> for u32 {
    fn from(register: StatusRegister) -> Self {
        u32::bit(31, register.flag_negative)
            | u32::bit(30, register.flag_zero)
            | u32::bit(29, register.flag_carry)
            | u32::bit(28, register.flag_overflow)
            | u32::bit(7, register.irq_disable)
            | u32::bit(6, register.fiq_disable)
            | u32::bit(5, register.thumb)
            | register.mode as u32
    }
}

impl TryFrom<u32> for StatusRegister {
    type Error = &'static str;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        Ok(Self {
            mode: Mode::from_u32(raw & 0x1F).ok_or("Invalid mode in loaded status register")?,
            thumb: raw.bit_is_set(5),
            fiq_disable: raw.bit_is_set(6),
            irq_disable: raw.bit_is_set(7),
            flag_overflow: raw.bit_is_set(28),
            flag_carry: raw.bit_is_set(29),
            flag_zero: raw.bit_is_set(30),
            flag_negative: raw.bit_is_set(31),
        })
    }
}

/// The ARM7TDMI (ARMv4) CPU used as the primary processor in the Game Boy
/// Advance.
pub struct Cpu {
    /// All numbered CPU registers, both universally accessible and banked.  The
    /// 16 registers for `System` and `User` mode, `r0`&ndash;`r15`, appear
    /// first, followed by the banked registers for the following modes in
    /// order: `FastInterrupt`, `Interrupt`, `Supervisor`, `Abort`, and
    /// `Undefined`.  The register file is only externally accessible by
    /// indexing the CPU.
    registers: [u32; 31],
    /// The Program Status Registers, in both current and banked forms.  The
    /// Current Program Status Register (CPSR) is stored at index `0` and is
    /// accessible from all modes, storing auxiliary processor state for the
    /// current mode.  The banked Saved Program Status Registers (SPSR), which
    /// store the value of the CPSR prior to a mode switch, are stored in
    /// subsequent indices in the following order: `FastInterrupt`, `Interrupt`,
    /// `Supervisor`, `Abort`, and `Undefined`.
    pub status: [StatusRegister; 6],
}

impl Cpu {
    /// Compute the index of the register with the specified number for the
    /// current mode in the register file.
    fn register_index(&self, register: RegisterNumber) -> usize {
        let raw_idx = register.0 as usize;

        match self.status[0].mode {
            // FIQ mode banks registers 8-14, differently from the other banked modes.
            Mode::FastInterrupt if (8..=14_usize).contains(&raw_idx) => raw_idx + 8,
            // Other privileged modes only bank r13 and r14.
            _ if raw_idx != 13 && raw_idx != 14 => raw_idx,
            Mode::Interrupt => raw_idx + 11,
            Mode::Supervisor => raw_idx + 13,
            Mode::Abort => raw_idx + 15,
            Mode::Undefined => raw_idx + 17,
            _ => raw_idx,
        }
    }
}

impl Index<RegisterNumber> for Cpu {
    type Output = u32;

    /// Access the register with the specified number for the current mode.
    fn index(&self, register: RegisterNumber) -> &Self::Output {
        &self.registers[self.register_index(register)]
    }
}

impl IndexMut<RegisterNumber> for Cpu {
    /// Access the register with the specified number for the current mode.
    fn index_mut(&mut self, register: RegisterNumber) -> &mut Self::Output {
        &mut self.registers[self.register_index(register)]
    }
}
