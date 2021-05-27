use crate::{
    bit_twiddling::BitTwiddling,
    cpu::{
        instruction,
        instruction::{BlockTransferMode, DataOperand, DataTransferOptions, ShiftType, SingleTransferType},
        CoprocessorRegister, RegisterNumber,
    },
};
use std::fmt;

/// Format an optional instruction field, returning the specified string if the
/// value of the field is `true` and an empty string otherwise.
fn optional_field(is_set: bool, set_value: &str) -> &str {
    if is_set {
        set_value
    } else {
        ""
    }
}

/// The names of the architectural registers in all modes, where the index into
/// this array corresponds with the register number.
const REGISTER_NAMES: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
];

impl fmt::Display for RegisterNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", REGISTER_NAMES[self.0 as usize])
    }
}

impl fmt::Display for CoprocessorRegister {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "c{}", self.0)
    }
}

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
    "and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn",
];

impl fmt::Display for instruction::ArithmeticOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", ARITHMETIC_OPERATION_MNEMONICS[*self as usize])
    }
}

/// The Assembly mnemonics used for each register `ShiftType`.
const SHIFT_TYPE_MNEMONICS: [&str; 4] = ["lsl", "lsr", "asr", "ror"];

impl fmt::Display for DataOperand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Immediate(value) => write!(f, "#{:#X}", value),
            Self::ShiftImmediate(shift_type, shift_amount, source) => {
                let shift = if shift_type == ShiftType::RotateRight && shift_amount == 0 {
                    // "ror #0" has the special form "rrx" involving the carry flag.
                    ",rrx".to_owned()
                } else if shift_type == ShiftType::LogicalShiftLeft && shift_amount == 0 {
                    // "lsl #0" is a no-op, so we don't need to disassemble it at all.
                    "".to_owned()
                } else {
                    let mnemonic = SHIFT_TYPE_MNEMONICS[shift_type as usize];
                    format!(",{} #{}", mnemonic, shift_amount)
                };
                write!(f, "{}{}", source, shift)
            }
            Self::ShiftRegister(shift_type, shift_register, source) => {
                let shift_mnemonic = SHIFT_TYPE_MNEMONICS[shift_type as usize];
                write!(f, "{},{} {}", source, shift_mnemonic, shift_register)
            }
        }
    }
}

/// Format the register list used in `BlockDataTransfer` instructions,
/// expressing series of subsequent registers using interval notation.
fn format_register_list(registers: u16) -> String {
    let mut intervals = Vec::new();
    let mut reg = 0;
    while reg < 16 {
        // Find the current register interval.
        let range_start = reg;
        let mut range_end = u8::MAX;
        while reg < 16 && registers.bit_is_set(reg) {
            range_end = reg;
            reg += 1;
        }

        // Format the register interval according to its size.
        if range_start == range_end {
            intervals.push(RegisterNumber(range_start).to_string());
        } else if range_end != u8::MAX {
            intervals.push(format!("{}-{}", RegisterNumber(range_start), RegisterNumber(range_end)));
        }

        reg += 1;
    }

    intervals.join(",")
}

/// Format the representation of a memory address as a signed offset from the
/// value stored in a register.  The `options` and `offset` read by this
/// function must be read from a data-transfer operation.
fn format_signed_address(options: &DataTransferOptions, offset: &DataOperand) -> String {
    let offset_sign = if options.add_offset { '+' } else { '-' };
    let offset_repr = match offset {
        DataOperand::Immediate(0) => "".to_owned(),
        DataOperand::Immediate(off) => format!(",#{}{:#X}", offset_sign, off),
        _ => format!(",{}{}", offset_sign, offset),
    };
    let write_suffix = optional_field(options.write_back, "!");

    if options.pre_index {
        format!("[{}{}]{}", options.base, offset_repr, write_suffix)
    } else {
        format!("[{}]{}", options.base, offset_repr)
    }
}

impl fmt::Display for instruction::BlockDataTransfer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mnemonic = if self.opt.load { "ldm" } else { "stm" };
        let write_suffix = optional_field(self.opt.write_back, "!");
        let mode_suffix = optional_field(self.mode != BlockTransferMode::Normal, "^");

        let (suffix1, suffix2) = if self.opt.base.0 == 13 {
            // Use different suffixes when operations are being performed on the stack.
            let stack_type = if self.opt.load == self.opt.pre_index { 'e' } else { 'f' };
            let stack_direction = if self.opt.load == self.opt.add_offset { 'd' } else { 'a' };
            (stack_type, stack_direction)
        } else {
            let increment = if self.opt.add_offset { 'i' } else { 'd' };
            let offset_timing = if self.opt.pre_index { 'b' } else { 'a' };
            (increment, offset_timing)
        };

        write!(
            f,
            "{}{}{}{} {}{},{{{}}}{}",
            mnemonic,
            self.condition,
            suffix1,
            suffix2,
            self.opt.base,
            write_suffix,
            format_register_list(self.registers),
            mode_suffix
        )
    }
}

impl fmt::Display for instruction::Branch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let link_mnemonic = optional_field(self.link, "l");
        write!(f, "b{}{} #{:+}", link_mnemonic, self.condition, self.offset)
    }
}

impl fmt::Display for instruction::BranchAndExchange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bx{} {}", self.condition, self.source)
    }
}

impl fmt::Display for instruction::CoprocessorDataOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let info_suffix = if self.opt.info == 0 {
            "".to_owned()
        } else {
            format!(",{}", self.opt.info)
        };

        write!(
            f,
            "cdp{} p{},{},{},{},{}{}",
            self.condition,
            self.opt.coprocessor,
            self.opt.operation,
            self.destination,
            self.opt.operand1,
            self.opt.operand2,
            info_suffix
        )
    }
}

impl fmt::Display for instruction::CoprocessorDataTransfer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mnemonic = if self.opt.load { "ldc" } else { "stc" };
        let length_suffix = optional_field(self.transfer_length, "l");
        let address = format_signed_address(&self.opt, &self.offset);

        write!(
            f,
            "{}{}{} p{},{},{}",
            mnemonic, self.condition, length_suffix, self.coprocessor, self.target, address
        )
    }
}

impl fmt::Display for instruction::DataProcessing {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use instruction::ArithmeticOperation::*;
        let cpsr_suffix = optional_field(self.set_cpsr, "s");

        match self.operation {
            // Single-operand instructions.
            Move | MoveInverse => write!(
                f,
                "{}{}{} {},{}",
                self.operation, self.condition, cpsr_suffix, self.destination, self.operand2
            ),
            // Dual-operand instructions that do not produce a result and implicitly set the CPSR.
            CompareSubtract | CompareAdd | Test | TestEqual => write!(
                f,
                "{}{} {},{}",
                self.operation, self.condition, self.operand1, self.operand2
            ),
            // Dual-operand instructions that produce a result and may or may not set the CPSR.
            _ => write!(
                f,
                "{}{}{} {},{},{}",
                self.operation, self.condition, cpsr_suffix, self.destination, self.operand1, self.operand2
            ),
        }
    }
}

impl fmt::Display for instruction::Multiply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let suffix = optional_field(self.set_cpsr, "s");
        let common = format!(
            "{}{} {},{},{}",
            self.condition, suffix, self.destination, self.multiplicand2, self.multiplicand1
        );

        if self.accumulate {
            write!(f, "mla{},{}", common, self.addend)
        } else {
            write!(f, "mul{}", common)
        }
    }
}

impl fmt::Display for instruction::MultiplyLong {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sign_prefix = if self.signed { 's' } else { 'u' };
        let mnemonic = if self.accumulate { "mlal" } else { "mull" };
        let suffix = optional_field(self.set_cpsr, "s");

        write!(
            f,
            "{}{}{}{} {},{},{},{}",
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
        write!(f, "mrs{} {},{}", self.condition, self.destination, psr_name)
    }
}

impl fmt::Display for instruction::RegisterPsrTransfer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let psr_name = if self.use_spsr { "spsr" } else { "cpsr" };
        let flag_suffix = optional_field(self.flags_only, "_flg");
        write!(f, "msr{} {}{},{}", self.condition, psr_name, flag_suffix, self.source)
    }
}

impl fmt::Display for instruction::SingleDataSwap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let byte_suffix = optional_field(self.swap_byte, "b");
        write!(
            f,
            "swp{}{} {},{},[{}]",
            self.condition, byte_suffix, self.destination, self.source, self.address
        )
    }
}

impl fmt::Display for instruction::SingleDataTransfer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mnemonic = if self.opt.load { "ldr" } else { "str" };
        let user_suffix = optional_field(!self.opt.pre_index && self.opt.write_back, "t");
        let address = format_signed_address(&self.opt, &self.offset);

        let size_suffix = match self.transfer_type {
            SingleTransferType::UnsignedByte => "b",
            SingleTransferType::SignedByte => "sb",
            SingleTransferType::UnsignedHalfWord => "h",
            SingleTransferType::SignedHalfWord => "sh",
            SingleTransferType::Word => "",
        };

        write!(
            f,
            "{}{}{}{} {},{}",
            mnemonic, self.condition, size_suffix, user_suffix, self.target, address
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
