/* Copyright (c) 2022 Benjamin John Mordaunt
 *     The OpenNitro Project
 */
#![no_std]
#![no_main]
#![no_builtins]
#![feature(link_llvm_intrinsics)]
#![feature(naked_functions)]

use core::arch::asm;

// (from 20BCh in arm7bios)
// Decrypt a single 64-bit word using the
// Blowfish algorithm (also known as KEY1).
// Parameters:
//     - key: u32 *
//       A concatenation of P-array and S-boxes,
//       generated typically from the gamecode.
//     - L: u32 *
//       The MSB of the 64-bit word to decrypt.
//     - R: u32 *
//       The LSB of the 64-bit word to decrypt.
// Invariants:
//     1) L = R + 4 (bytes).

#[instruction_set(arm::t32)]
#[no_mangle]
pub unsafe extern "C" fn Blowfish_Decrypt64 (
    key: *mut u32,
    l: *mut u32,
    r: *mut u32
) {
    let mut lderef: u32 = *l;
    let mut rderef: u32 = *r;
    let mut round_count: i32 = 0x11;
    let mut word_in_flight: *mut u32;

    while {
        word_in_flight = (key.offset(round_count as isize) as u32 ^ lderef) as *mut u32;
        lderef = Blowfish_FeistelRound(
            key,
            word_in_flight);
        lderef = lderef ^ rderef;
        round_count -= 1;
        rderef = word_in_flight as u32;

        1 < round_count
    } {}

    rderef = *key.offset(1);
    *l = *key ^ word_in_flight as u32;
    *r = rderef ^ lderef;
}

#[instruction_set(arm::t32)]
#[no_mangle]
pub unsafe extern "C" fn Blowfish_FeistelRound (
    keyarea: *mut u32,
    word_in_flight: *mut u32
) -> u32 {
    let zero_shift: *const u32 = (
        (word_in_flight as u32 & 0xFF) * 4 + keyarea as u32 + 0xC48
    ) as *const u32;
    let eight_shift: *const u32 = (
        (word_in_flight as u32 >> 8 & 0xFF) * 4 + keyarea as u32 + 0x848
    ) as *const u32;
    // Note that in the original binary, there is an interesting
    // obfuscation here: x * 4 is replaced by (x << 0x18) >> 0x16
    // Should we match this?
    let sixteen_shift: *const u32 = (
        (word_in_flight as u32 >> 16) * 4 + keyarea as u32 + 0x448
    ) as *const u32;
    let twenty_four_shift: *const u32 = (
        (word_in_flight as u32 >> 24) * 4 + keyarea as u32 + 0x48
    ) as *const u32;
    
    *zero_shift + (*eight_shift ^ *twenty_four_shift + *sixteen_shift)
}

// (from 30e4h in arm7bios)
// Simply copy data from src to dat. The original function operated "quickly"
// (using the ldmlt and stmlt opcodes) on 8 * u32 chunks (256-bits), then copied
// any remainder "slowly" (using mov). With the privilege of modern compilers, we
// shouldn't have to worry about such meta-programming.
#[no_mangle]
pub unsafe extern "C" fn CpuFastCopy (
    src: *const u32,
    dst: *mut u32,
    size: u32
) {
    let dst_slice = core::slice::from_raw_parts_mut(dst, size as usize);
    let src_slice = core::slice::from_raw_parts(src, size as usize);

    // If this particular bit is set in the size field, instead of performing a copy,
    // just set all words in the destination range with src[0].
    if ((size >> 0x18) & 1) != 0 {
        for elem in dst_slice {
            *elem = *src;
        }
    } else {
        dst_slice.copy_from_slice(&src_slice);
    }
}

// --- BEGIN ULTRA-LOW LEVEL ---
// Functions which are to be implemented in raw assembly,
// because they e.g. communicate with CP15, manipulate system
// registers or do similarly strange things.

// (from 2d78h in arm7bios)
// This function serves two main purposes:
// 1) Set up the Saved Program State Registers (SPSR)
//    so that the processor is ready to handle exceptions
//    in both the Supervisor and IRQ modes, with valid stack
//    pointers. Stack bases:
//     - Supervisor: 0x380ffdc
//     - IRQ:        0x380ffb0
//     - System:     0x380ff00
// 2) Zero 200h bytes between 0x3FFFE00..0x4000000 ... for some reason.
#[naked]
#[no_mangle]
pub unsafe extern "C" fn InitARM7Stacks() {
    asm!(
        ".code 32",             // start out in arm mode
        "mov r0, #0xd3",        // enter supervisor mode
        "msr cpsr_fsxc, r0",    // ...
        "ldr sp, =0x00002e34", // set stack ptr for this mode
        "mov lr, #0",
        "msr spsr_fsxc, lr",
        "mov r0, 0xd2",
        "msr cpsr_fsxc, r0",
        "ldr sp, =0x00002e30",
        "mov lr, #0",
        "msr spsr_fsxc, lr",
        "mov r0, 0x5f",
        "msr cpsr_fsxc, r0",
        "ldr sp, =0x00002e2c",
        "mov r4, #0x4000000",
        "add r0, pc, #1",
        "bx r0",
        ".code 16",            // switch to thumb mode
        "movs r0, #0",
        "ldr r1, [pc, #0x104]",
        "0: str r0, [r4, r1]",
        "adds r1, #4",
        "blt.n 0",
        "bx lr",
        options(noreturn)
    );
}

// (from 1164h in arm7bios) 
// A safety shim executed before BIOS functions to ensure the caller
// originates from a legal call site. This is so low level that I'm
// not even going to attempt to do this in anything other than asm.
#[naked]
#[no_mangle]
pub unsafe extern "C" fn BiosSafeShim () {
    asm!(
        "tst lr, #0xff000000",
        "bxeq ip",
        "mov ip, #0",
        "mov r3, #0",
        "mov r2, #0",
        "mov r1, #0",
        "mov r0, #0", 
        "mov lr, #4",
        "bx lr",
        options(noreturn)
    );
}

#[panic_handler]
fn null_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
