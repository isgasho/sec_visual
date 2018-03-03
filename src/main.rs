#[macro_use]extern crate conrod;
extern crate  unicorn;

mod gui;
mod executor;

fn main() {
    let mut exp = Box::new(executor::Exploit::new());

    //executor::emu_one();
    gui::main(&mut exp);
}
