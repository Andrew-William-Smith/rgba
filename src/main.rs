extern crate derive_more;
extern crate num_derive;

use env_logger::Env;
use log::{debug, info, Level};
use rgba::cpu::Cpu;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "rgba", about = "A Game Boy Advance emulator written in Rust.", author)]
struct CommandLine {
    /// The minimum level of debugging messages to print to the console.
    /// Options in increasing level of detail are: Error, Warn, Info, Debug,
    /// Trace.  Can be overridden by setting the RUST_LOG environment variable
    /// to one of the aforementioned values.
    #[structopt(short, long, default_value = "Warn")]
    log_level: Level,
    /// The ROM (.gba) file to load upon starting the emulator.
    #[structopt(parse(from_os_str))]
    rom_file: Option<PathBuf>,
}

fn main() {
    // Initialise logging and read command line arguments.
    let args = CommandLine::from_args();
    env_logger::Builder::from_env(Env::default().default_filter_or(args.log_level.to_string())).init();
    info!("Welcome to RGBA!  Launching from command line now.");
    debug!("Arguments: {:?}", args);

    let cpu = Cpu::default();
    println!("{}", cpu);
}
