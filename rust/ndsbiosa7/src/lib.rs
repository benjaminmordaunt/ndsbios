/* Copyright (c) 2022 Benjamin John Mordaunt
 *     The OpenNitro Project
 */
#![no_std]

use core::intrinsics::transmute;

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
    key: *const u32,
    l: *mut u32,
    r: *mut u32
) {
    let mut lderef: u32 = *l;
    let mut rderef: u32 = *r;
    let mut round_count: i32 = 0x11;
    let mut tmp1: u32;

    while {
        tmp1 = *key.offset(round_count as isize) ^ lderef;
        lderef = Blowfish_FeistelRound(
            transmute::<*const u32, i32>(key),
            tmp1);
        lderef = lderef ^ rderef;
        round_count -= 1;
        rderef = tmp1;

        1 < round_count
    } {}

    rderef = *key.offset(1);
    *l = *key.offset(0) ^ tmp1;
    *r = rderef ^ lderef;
}

#[instruction_set(arm::t32)]
#[no_mangle]
pub unsafe extern "C" fn Blowfish_FeistelRound (
    keyarea: i32,
    word_in_flight: u32
) -> u32 {
    let zero_shift: *const i32 = transmute::<u32, *const i32>(
        (word_in_flight & 0xFF) * 4 + keyarea as u32 + 0xC48
    );
    let eight_shift: *const i32 = transmute::<u32, *const i32>(
        (word_in_flight >> 8 & 0xFF) * 4 + keyarea as u32 + 0x848
    );
    // Note that in the original binary, there is an interesting
    // obfuscation here: x * 4 is replaced by (x << 0x18) >> 0x16
    // Should we match this?
    let sixteen_shift: *const i32 = transmute::<u32, *const i32>(
        (word_in_flight >> 16) * 4 + keyarea as u32 + 0x448
    );
    let twenty_four_shift: *const i32 = transmute::<u32, *const i32>(
        (word_in_flight >> 24) * 4 + keyarea as u32 + 0x48
    );
    
    (*zero_shift + (*eight_shift ^ *twenty_four_shift + *sixteen_shift)) as u32
}
