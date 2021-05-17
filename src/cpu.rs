pub mod instruction;

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
