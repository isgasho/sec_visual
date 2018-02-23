#[macro_use]extern crate conrod;
extern crate  unicorn;

mod gui;
mod executor;

fn main() {
    executor::emu_one();
    gui::main();
}
