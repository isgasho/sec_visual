use unicorn;
use unicorn::{Cpu, CpuX86, RegisterX86};

pub fn emu_one() {
    // inc ecx;
    // dec edx;
    // mov (ebp), eax
    // mov 0xdeadbeef, eax;
    // mov eax, [0x2000];
    // mov [0x3000], eax;
    let ins = vec![
        0x41, 0x4a, 0x8b, 0x45, 0x00, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xA3, 0x00, 0x20, 0x00, 0x00,
        0xA1, 0x00, 0x30, 0x00, 0x00,
    ];

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("Failed to start emulator");

    let _ = emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL);
    let _ = emu.mem_write(0x1000, &ins);

    let _ = emu.reg_write_i32(RegisterX86::EAX, 0);
    let _ = emu.reg_write_i32(RegisterX86::ECX, -10);
    let _ = emu.reg_write_i32(RegisterX86::EDX, -10);
    let _ = emu.reg_write_i32(RegisterX86::EBP, 0x3000);

    // Note that the value is invalid for memory read
    let callback = |_: &unicorn::Unicorn,
                    mem_type: unicorn::MemType,
                    address: u64,
                    size: usize,
                    value: i64| {
        println!(
            "addr: {:x}, type: {:?}, value: {:x}",
            address, mem_type, value
        );
        false
    };

    let hook = emu.add_mem_hook(unicorn::MemHookType::MEM_ALL, 0, 0x4000, callback)
        .unwrap();

    let _ = emu.mem_write(0x3000, &[0x01, 0x02, 0x03, 0x04]);
    let _ = emu.emu_start(
        0x1000,
        (0x1000 + ins.len()) as u64,
        10 * unicorn::SECOND_SCALE,
        1000,
    );

    emu.remove_hook(hook).unwrap();

    println!(
        "EAX: {:x}, ECX: {}, EDX: {}",
        emu.reg_read_i32(RegisterX86::EAX).unwrap(),
        emu.reg_read_i32(RegisterX86::ECX).unwrap(),
        emu.reg_read_i32(RegisterX86::EDX).unwrap()
    );
}
