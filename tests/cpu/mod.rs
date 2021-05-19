#![allow(unused_imports)]

mod decode_instruction;

/// A simple macro to assert that the decoding of a number of raw instructions
/// of the same type is working properly.
#[macro_export]
macro_rules! decode_succeeds {
    ($type:ident, $($bytecode:literal => $decoded:expr => $disassembly:expr),+$(,)?) => {
        $(
            use Condition::*;
            let bytecode: u32 = $bytecode;
            let result = Instruction::decode(bytecode);
            match result {
                Some(Instruction::$type(inst)) => {
                    assert_eq!(inst, $decoded);
                    assert_eq!(inst.to_string(), $disassembly);
                }
                Some(inst) => panic!("Instruction decoded to wrong type!  {:#X} => {}", bytecode, inst),
                None => panic!("Instruction failed to decode!"),
            };
        )+
    }
}
