mod decode_instruction;

/// A simple macro to assert that the decoding of a number of raw instructions
/// of the same type is working properly.
#[macro_export]
macro_rules! decode_succeeds {
    ($type:ident, $($bytecode:literal => $decoded:expr => $disassembly:expr),+$(,)?) => {
        $(
            let result = Instruction::decode($bytecode);
            match result {
                Some(Instruction::$type(inst)) => {
                    assert_eq!(inst, $decoded);
                    assert_eq!(inst.to_string(), $disassembly);
                }
                Some(_) => panic!("Instruction decoded to wrong type!"),
                None => panic!("Instruction failed to decode!"),
            };
        )+
    }
}
