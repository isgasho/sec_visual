#[macro_use]extern crate conrod;
extern crate  unicorn;

mod gui;
mod executor;

fn main() {
    let exp = executor::Exploit::new();
    executor::emu_one();
    gui::main();
}
