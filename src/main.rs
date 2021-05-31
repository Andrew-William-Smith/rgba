extern crate derive_more;
extern crate num_derive;

use rgba::cpu::Cpu;

fn main() {
    let mut _cpu = Cpu::default();
    println!("{}", _cpu);
}
