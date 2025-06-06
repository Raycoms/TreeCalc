use std::time::Instant;
use hmac::Hmac;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use crate::simulation::simulator::Simulator;
use crate::simulation::validator::Validator;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

pub(crate) async fn main() {

    // Fanout we're considering.
    let m = 312;

    // Set up simulator connections.

    // Random 100KB block data (about realistic).
    let mut proposal = vec![0u8; 100_000];
    OsRng.fill_bytes(&mut proposal);

    let mut simulator = Simulator::new(m, &proposal);
    let public_keys = simulator.prepare().await;
    println!("Finished preparing Simulator");

    // Set up validator connections.
    let mut validator = Validator::new(m, &proposal, public_keys);
    validator.prepare().await;
    println!("Finished preparing Validator");

    // Send out network messages of simulator for the validator to process.
    simulator.run().await;
    println!("Started up Simulator");

    // Actually run the validator and measure time it took.
    let time_now = Instant::now();
    validator.run().await;
    println!("Now: {}", time_now.elapsed().as_millis())
}