use libafl_bolts::rands::Rand;

/// Helper function that gives a new random input of length 8 (which seems sensible for
/// most api parameters), starting out with sort-of ascii.
pub fn new_rand_input<R: Rand>(rand: &mut R) -> Vec<u8> {
    let r = rand.next();
    (0..8).map(|i| (r >> i) as u8 & 0x7f).collect()
}
