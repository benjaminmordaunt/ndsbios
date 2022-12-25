/* Copyright (c) 2022 Benjamin John Mordaunt
 *     The OpenNitro Project
 */
#![no_std]
#![no_main]

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

#[panic_handler]
fn null_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
