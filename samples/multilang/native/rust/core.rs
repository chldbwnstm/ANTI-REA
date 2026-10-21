#![no_std]

// A bounded no_std C ABI core; not arbitrary Cargo dependencies or Rust runtime.
#[no_mangle]
pub extern "C" fn native_transform(x: u32, y: u32) -> u64 {
    let mut value = ((x as u64) << 17) ^ ((y as u64).wrapping_add(0x9183));
    for i in 0..4u32 {
        value ^= value >> 13;
        value = value.wrapping_mul(0x100000001b3);
        if (value ^ i as u64) & 1 != 0 {
            value = value.wrapping_add(((y as u64) << 7).wrapping_add(i as u64));
        } else {
            value ^= ((x as u64) << 11).wrapping_add(0x51ed);
        }
    }
    value.wrapping_add((x as u64) ^ y as u64)
}
