use unicorn;
use unicorn::{Cpu, CpuX86, RegisterX86};
use std::ops::{Index, IndexMut};
use std::convert::From;

#[derive(Debug, Clone, Copy)]
enum X86RegsIdx {
    EAX = 0,
    EBX,
    ECX,
    EDX,
    ESI,
    EDI,
    EBP,
    ESP,
    EIP,
    EFLAGS,
}

impl From<usize> for X86RegsIdx {
    fn from(idx: usize) -> Self {
        let all = [
            X86RegsIdx::EAX,
            X86RegsIdx::EBX,
            X86RegsIdx::ECX,
            X86RegsIdx::EDX,
            X86RegsIdx::ESI,
            X86RegsIdx::EDI,
            X86RegsIdx::EBP,
            X86RegsIdx::ESP,
            X86RegsIdx::EIP,
            X86RegsIdx::EFLAGS,
        ];

        all[idx]
    }
}

pub struct X86Reg32 {
    regs: [u32; 10],
}

impl X86Reg32 {
    pub fn new() -> X86Reg32 {
        X86Reg32 { regs: [0; 10] }
    }

    pub fn len(&self) -> usize {
        10
    }

    // add code here
    pub fn read_from(&mut self, emu: &unicorn::CpuX86) {
        self[X86RegsIdx::EAX] = emu.reg_read_i32(RegisterX86::EAX).unwrap() as u32;
        self[X86RegsIdx::EBX] = emu.reg_read_i32(RegisterX86::EBX).unwrap() as u32;
        self[X86RegsIdx::ECX] = emu.reg_read_i32(RegisterX86::ECX).unwrap() as u32;
        self[X86RegsIdx::EDX] = emu.reg_read_i32(RegisterX86::EDX).unwrap() as u32;
        self[X86RegsIdx::ESI] = emu.reg_read_i32(RegisterX86::ESI).unwrap() as u32;
        self[X86RegsIdx::EDI] = emu.reg_read_i32(RegisterX86::EDI).unwrap() as u32;
        self[X86RegsIdx::EBP] = emu.reg_read_i32(RegisterX86::EBP).unwrap() as u32;
        self[X86RegsIdx::ESP] = emu.reg_read_i32(RegisterX86::ESP).unwrap() as u32;
        self[X86RegsIdx::EIP] = emu.reg_read_i32(RegisterX86::EIP).unwrap() as u32;
        self[X86RegsIdx::EFLAGS] = emu.reg_read_i32(RegisterX86::EFLAGS).unwrap() as u32;
    }

    pub fn to_string(&self, index: usize) -> String {
        format!("{:?}", X86RegsIdx::from(index))
    }
}

impl Index<usize> for X86Reg32 {
    type Output = u32;

    fn index(&self, idx: usize) -> &u32 {
        &self.regs[idx]
    }
}

impl Index<X86RegsIdx> for X86Reg32 {
    type Output = u32;

    fn index(&self, idx: X86RegsIdx) -> &u32 {
        &self.regs[idx as usize]
    }
}

impl IndexMut<X86RegsIdx> for X86Reg32 {
    fn index_mut(&mut self, idx: X86RegsIdx) -> &mut u32 {
        &mut self.regs[idx as usize]
    }
}

pub struct Mem32 {
    words: [i32; 512], // currently we support 1KB of memory, keep your examples simple
}

impl Mem32 {
    pub fn new() -> Mem32 {
        Mem32 { words: [0; 512] }
    }

    // update the memory
    pub fn update(&mut self, addr: u64, size: usize, value: i64) {}
}

pub struct Ins {
    pub dis: String, //Disassembly of the instruction
    pub bytes: Vec<u8>,
}

// This structure contains all the information about the current exploit to visualize
pub struct Exploit {
    emu: unicorn::CpuX86,
    pub ins: Vec<Ins>,
    pub cur_ins: usize,
    pub regs: X86Reg32,
    pub mem: Mem32,
}

impl Exploit {
    pub fn new() -> Exploit {
        let mut exp = Exploit {
            emu: CpuX86::new(unicorn::Mode::MODE_32).unwrap(),
            ins: vec![],
            cur_ins: 0,
            regs: X86Reg32::new(),
            mem: Mem32::new(),
        };

        exp.ins.push(Ins {
            dis: String::from("inc ecx"),
            bytes: vec![],
        });
        exp.ins.push(Ins {
            dis: String::from("dec ecx"),
            bytes: vec![],
        });
        exp.ins.push(Ins {
            dis: String::from("mov (ebp), eax"),
            bytes: vec![],
        });
        exp.ins.push(Ins {
            dis: String::from("mov 0xdeadbeef, eax"),
            bytes: vec![],
        });
        exp.ins.push(Ins {
            dis: String::from("mov eax, [0x2000]"),
            bytes: vec![],
        });
        exp.ins.push(Ins {
            dis: String::from("mov [0x3000], eax"),
            bytes: vec![],
        });

        exp.regs[X86RegsIdx::EAX] = 0xdeadbeefu32;
        exp
    }
}

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
