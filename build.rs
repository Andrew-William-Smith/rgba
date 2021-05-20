use std::{
    env,
    error::Error,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

/// Bit sequences that uniquely identify each instruction type.  These sequences
/// are combinations of bits `[27:20]` and `[7:4]` of each instruction type's
/// encoded sequence; when combined and processed in the order listed in the
/// ARM7TDMI-S data sheet, they allow for the type of an instruction to be
/// determined from a static table.  This table consists of two masks: one to
/// select the bits that pertain to the instruction type, and one to confirm
/// that those bits are correct.
const ENCODING_SELECT: [(usize, usize, &str); 10] = [
    (0b1100_0000_0000, 0b0000_0000_0000, "DataProcessing"),
    (0b1111_1011_1111, 0b0001_0000_0000, "PsrRegisterTransfer"),
    (0b1101_1011_1111, 0b0001_0010_0000, "RegisterPsrTransfer"),
    (0b1111_1100_1111, 0b0000_0000_1001, "Multiply"),
    (0b1111_1000_1111, 0b0000_1000_1001, "MultiplyLong"),
    (0b1111_1011_1111, 0b0001_0000_1001, "SingleDataSwap"),
    (0b1111_1111_1111, 0b0001_0010_0001, "BranchAndExchange"),
    // 0b1110_0100_1001, 0b0000_0000_1001 -> Halfword Data Transfer: Register Offset
    // 0b1110_0100_1001, 0b0000_0100_1001 -> Halfword Data Transfer: Immediate Offset
    (0b1100_0000_0000, 0b0100_0000_0000, "SingleDataTransfer"),
    // 0b1110_0000_0001, 0b0110_0000_0001 -> Undefined
    // 0b1110_0000_0000, 0b1000_0000_0000 -> Block Data Transfer
    (0b1110_0000_0000, 0b1010_0000_0000, "Branch"),
    // 0b1110_0000_0000, 0b1100_0000_0000 -> Coprocessor Data Transfer
    // 0b1111_0000_0001, 0b1110_0000_0000 -> Coprocessor Data Operation
    // 0b1111_0000_0001, 0b1110_0000_0001 -> Coprocessor Register Transfer
    (0b1111_0000_0000, 0b1111_0000_0000, "SoftwareInterrupt"),
];

/// The number of entries in the decode table.  Since each encoding select
/// sequence is 12 bits long, there are (2 ^ 12) possible sequences.
const DECODE_ENTRIES: usize = 4096;

/// The number of entries spanned by each entry in the level 1 instruction
/// decode lookup table.
const DECODE_L1_CHUNK_SIZE: usize = 16;

/// The number of entries in the level 1 decode lookup table.
const DECODE_L1_TABLE_SIZE: usize = DECODE_ENTRIES / DECODE_L1_CHUNK_SIZE;

/// Construct static instruction type decoding tables as documented on
/// `ENCODING_SELECT`.
fn build_decode_tables() -> Result<(), Box<dyn Error>> {
    // Determine the instruction type for each bit sequence.
    let mut instruction_types = [0; DECODE_ENTRIES];
    for (sequence, entry) in instruction_types.iter_mut().enumerate() {
        // Scan through the encoding select masks to find the last one that applies.
        let mut encoding = 0;
        ENCODING_SELECT
            .iter()
            .enumerate()
            .for_each(|(idx, (select, confirm, _))| {
                if (sequence & *select) == *confirm {
                    encoding = idx;
                }
            });
        *entry = encoding;
    }

    // Partition flat array into two segments depending upon the high 8 bits.
    let mut unique_chunks = Vec::new();
    let mut l1_table = [0; DECODE_L1_TABLE_SIZE];
    for (l1_idx, chunk) in instruction_types.chunks(DECODE_L1_CHUNK_SIZE).enumerate() {
        if let Some(idx) = unique_chunks.iter().position(|c| *c == chunk) {
            l1_table[l1_idx] = idx * DECODE_L1_CHUNK_SIZE;
        } else {
            // This is a new sequence, so we shall add it to the unique vector.
            l1_table[l1_idx] = unique_chunks.len() * DECODE_L1_CHUNK_SIZE;
            unique_chunks.push(chunk);
        }
    }

    // Create a file whither to write the generated output.
    let out_path = Path::new(&env::var("OUT_DIR")?).join("codegen_decode_tables.rs");
    let mut output = BufWriter::new(File::create(out_path)?);

    // We need the Instruction module to gain access to decoding functions.
    writeln!(
        &mut output,
        "type DecodeCallback = fn(RawInstruction, Condition) -> Option<Instruction>;"
    )?;

    // L1 decoding table, comprised of indexes into the L2 table.
    writeln!(
        &mut output,
        "const DECODE_L1_TABLE: [usize; {}] = [{}];",
        DECODE_L1_TABLE_SIZE,
        l1_table
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    )?;

    // L2 decoding table, associating select bytes to decoding callbacks.
    writeln!(
        &mut output,
        "const DECODE_L2_TABLE: [DecodeCallback; {}] = [",
        unique_chunks.len() * DECODE_L1_CHUNK_SIZE,
    )?;

    for chunk in unique_chunks {
        writeln!(
            &mut output,
            "    {},",
            chunk
                .iter()
                .map(|idx| format!("{}::decode", ENCODING_SELECT[*idx].2))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }
    writeln!(&mut output, "];")?;
    Ok(())
}

fn main() {
    build_decode_tables().expect("Failed to build instruction decoding tables!");
}
