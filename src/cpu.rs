use crate::bit_twiddling::BitTwiddling;

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
pub enum Mode {
    /// The standard mode of execution; this mode is unprivileged.
    User,
    /// A higher-priority interrupt mode (FIQ) that can preëmpt IRQ handlers.
    FastInterrupt,
    /// The mode in which general purpose interrupt (IRQ) handlers are executed.
    Interrupt,
    /// A privileged mode entered as the result of a software interrupt (`swi`).
    Supervisor,
    /// A mode entered after a data or instruction prefetch abort.
    Abort,
    /// A privileged mode entered by setting the mode bit in the CPSR; the only
    /// privileged mode that can be entered without an interrupt.
    System,
    /// A mode entered when an illegal instruction is encountered.
    Undefined,
}
