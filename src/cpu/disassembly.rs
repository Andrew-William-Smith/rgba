use crate::cpu::instruction;
use crate::cpu::instruction::ShiftType;
use std::fmt;

/// The Assembly mnemonics used for each execution `Condition`.
const CONDITION_MNEMONICS: [&str; 15] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "",
];

impl fmt::Display for instruction::Condition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", CONDITION_MNEMONICS[*self as usize])
    }
}

/// The Assembly mnemonics used for each `ArithmeticOperation`.
const ARITHMETIC_OPERATION_MNEMONICS: [&str; 16] = [
    "and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr",
    "mov", "bic", "mvn",
];

impl fmt::Display for instruction::ArithmeticOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", ARITHMETIC_OPERATION_MNEMONICS[*self as usize])
    }
}

/// The Assembly mnemonics used for each register `ShiftType`.
const SHIFT_TYPE_MNEMONICS: [&str; 4] = ["lsl", "lsr", "asr", "ror"];

impl fmt::Display for instruction::DataOperand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Immediate(value) => write!(f, "#{:#X}", value),
            Self::ShiftImmediate(shift_type, shift_amount, source) => {
                let shift = if shift_type == ShiftType::RotateRight && shift_amount == 0 {
                    // "ror #0" has the special form "rrx" involving the carry flag.
                    String::from(",rrx")
                } else if shift_type == ShiftType::LogicalShiftLeft && shift_amount == 0 {
                    // "lsl #0" is a no-op, so we don't need to disassemble it at all.
                    String::from("")
                } else {
                    let mnemonic = SHIFT_TYPE_MNEMONICS[shift_type as usize];
                    format!(",{} #{}", mnemonic, shift_amount)
                };
                write!(f, "r{}{}", source, shift)
            }
            Self::ShiftRegister(shift_type, shift_register, source) => {
                let shift_mnemonic = SHIFT_TYPE_MNEMONICS[shift_type as usize];
                write!(f, "r{},{} r{}", source, shift_mnemonic, shift_register)
            }
        }
    }
}

impl fmt::Display for instruction::Branch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let link_mnemonic = if self.link { "l" } else { "" };
        write!(f, "b{}{} #{:+}", link_mnemonic, self.condition, self.offset)
    }
}

impl fmt::Display for instruction::BranchAndExchange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bx{} r{}", self.condition, self.source)
    }
}

impl fmt::Display for instruction::DataProcessing {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use instruction::ArithmeticOperation::*;
        let cpsr_suffix = if self.set_cpsr { "s" } else { "" };

        match self.operation {
            // Single-operand instructions.
            Move | MoveInverse => write!(
                f,
                "{}{}{} r{},{}",
                self.operation, self.condition, cpsr_suffix, self.destination, self.operand2
            ),
            // Dual-operand instructions that do not produce a result and implicitly set the CPSR.
            CompareSubtract | CompareAdd | Test | TestEqual => write!(
                f,
                "{}{} r{},{}",
                self.operation, self.condition, self.operand1, self.operand2
            ),
            // Dual-operand instructions that produce a result and may or may not set the CPSR.
            _ => write!(
                f,
                "{}{}{} r{},r{},{}",
                self.operation,
                self.condition,
                cpsr_suffix,
                self.destination,
                self.operand1,
                self.operand2
            ),
        }
    }
}

impl fmt::Display for instruction::Multiply {
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

impl fmt::Display for instruction::MultiplyLong {
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

impl fmt::Display for instruction::PsrRegisterTransfer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let psr_name = if self.use_spsr { "spsr" } else { "cpsr" };
        write!(
            f,
            "mrs{} r{},{}",
            self.condition, self.destination, psr_name
        )
    }
}

impl fmt::Display for instruction::RegisterPsrTransfer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let psr_name = if self.use_spsr { "spsr" } else { "cpsr" };
        let flag_suffix = if self.flags_only { "_flg" } else { "" };
        write!(
            f,
            "msr{} {}{},{}",
            self.condition, psr_name, flag_suffix, self.source
        )
    }
}

impl fmt::Display for instruction::SingleDataSwap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let byte_suffix = if self.swap_byte { "b" } else { "" };
        write!(
            f,
            "swp{}{} r{},r{},[r{}]",
            self.condition, byte_suffix, self.destination, self.source, self.address
        )
    }
}

impl fmt::Display for instruction::SoftwareInterrupt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "swi{} #{:#X}", self.condition, self.comment)
    }
}

impl fmt::Debug for instruction::Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
