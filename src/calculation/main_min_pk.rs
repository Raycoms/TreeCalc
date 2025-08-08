#![allow(non_snake_case)]
#![allow(dead_code)]

use std::fs::File;
use std::io;
use std::io::{BufRead, Write};
use std::time::Instant;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use rand_core::RngCore;
use hex::encode;
use hex::decode;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
pub const MSG: &[u8] = b"blst is such a blast";


// Signing 1000000 times took: 311.503424024s
// Verifying 1000000 times took: 882.21440825s

// Aggregating Public Keys 10 times took: 6.031µs
// Aggregating Public Keys 100 times took: 46.447µs
// Aggregating Public Keys 1000 times took: 470.296µs
// Aggregating Public Keys 10000 times took: 4.72241ms
// Aggregating Public Keys 100000 times took: 46.405487ms
// Aggregating Public Keys 1000000 times took: 460.724574ms

// Aggregating Signatures 10 times took: 14.267µs
// Aggregating Signatures 100 times took: 107.172µs
// Aggregating Signatures 1000 times took: 1.085346ms
// Aggregating Signatures 10000 times took: 10.856701ms
// Aggregating Signatures 100000 times took: 108.272533ms
// Aggregating Signatures 1000000 times took: 1.068981688s

pub(crate) fn main() {
    println!("Hello, world!");
    let _ = gen_keys();
    let (public_keys, private_keys) = load_keys();
    let signatures = bench_sign(&private_keys);
    bench_single_verify(&signatures, &public_keys);
    bench_agg(&signatures, &public_keys);
}

// Generate a million keys and write to file.
pub fn gen_keys()  -> io::Result<()> {
    let mut file = File::create("../../sigs_min_pk.txt")?;

    for _ in 0..1_000_000 {
        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let pvt_key = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pub_key = pvt_key.sk_to_pk();

        file.write_all(format!("{} {}\n", encode(pvt_key.to_bytes()), encode(pub_key.to_bytes())).as_bytes())?;
    }
    Ok(())
}

// Load keys from file.
pub fn load_keys() -> (Vec<PublicKey>, Vec<SecretKey>) {
    let file = File::open("../../sigs_min_pk.txt").unwrap();
    let reader = io::BufReader::new(file);

    let mut private_keys = Vec::new();
    let mut public_keys = Vec::new();

    for line in reader.lines() {
        let line = line.unwrap();
        let content : Vec<_> = line.split(" ").collect();
        private_keys.push(SecretKey::from_bytes(decode(content[0]).unwrap().as_ref()).unwrap());
        public_keys.push(PublicKey::from_bytes(decode(content[1]).unwrap().as_ref()).unwrap());
        if private_keys.len() >= 1_000_000 {
            break;
        }
    }
    (public_keys, private_keys)
}

// Bench mark signing.
pub fn bench_sign(private_keys: &Vec<SecretKey>) -> Vec<Signature> {
    let start = Instant::now();
    let mut signatures = vec![];
    for pvt_key in private_keys {
        signatures.push(pvt_key.sign(MSG, DST, &[]));
    }
    println!("Signing {} times took: {:?}", signatures.len(), start.elapsed());
    signatures
}

// Benchmark verifying.
fn bench_single_verify(signatures: &Vec<Signature>, public_keys: &Vec<PublicKey>) {
    let start = Instant::now();
    for (index, sig) in signatures.iter().enumerate() {
        sig.verify(false, MSG, DST, &[],&public_keys[index], false);
    }
    println!("Verifying {} times took: {:?}", signatures.len(), start.elapsed());
}

fn bench_agg(signatures: &Vec<Signature>, public_keys: &Vec<PublicKey>) {
    for size in [10,100,1000,10_000, 100_000, 1_000_000] {
        let subset = &public_keys.iter().take(size).collect::<Vec<_>>()[..];
        let start = Instant::now();
        AggregatePublicKey::aggregate(&subset, false).unwrap();
        println!("Aggregating Public Keys {} times took: {:?}", size, start.elapsed());
    }

    for size in [10,100,1000,10_000, 100_000, 1_000_000] {
        let subset = &signatures.iter().take(size).collect::<Vec<_>>()[..];
        let start = Instant::now();
        AggregateSignature::aggregate(&subset, false).unwrap();
        println!("Aggregating Signatures {} times took: {:?}", size, start.elapsed());
    }
}