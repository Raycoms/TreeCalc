use std::fs::File;
use std::io;
use std::io::{BufRead, Write};
use std::time::Instant;
use blst::BLST_ERROR;
use blst::min_sig::{PublicKey, SecretKey, Signature};
use rand_core::RngCore;
use hex::encode;
use hex::decode;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
pub const MSG: &[u8] = b"blst is such a blast";

// Signing 1000000 times took: 143.445260813s
// Verifying 1000000 times took: 748.658190677s

// Signing 1000000 times took: 139.163173579s

// Aggregating Public Keys 10 times took: 13.285µs
// Aggregating Public Keys 100 times took: 105.918µs
// Aggregating Public Keys 1000 times took: 1.070118ms
// Aggregating Public Keys 10000 times took: 10.800773ms
// Aggregating Public Keys 100000 times took: 107.441397ms
// Aggregating Public Keys 1000000 times took: 1.075961091s

// Aggregating Signatures 10 times took: 9.608µs
// Aggregating Signatures 100 times took: 45.946µs
// Aggregating Signatures 1000 times took: 462.418µs
// Aggregating Signatures 10000 times took: 4.599028ms
// Aggregating Signatures 100000 times took: 46.989987ms
// Aggregating Signatures 1000000 times took: 474.375127ms

// Fast Aggregate Verify 10 times took: 1.792603ms
// Fast Aggregate Verify 100 times took: 889.038µs
// Fast Aggregate Verify 1000 times took: 1.89756ms
// Fast Aggregate Verify 10000 times took: 11.562872ms
// Fast Aggregate Verify 100000 times took: 109.068239ms
// Fast Aggregate Verify 1000000 times took: 1.07738328s

pub(crate) fn main() {
    println!("Hello, world!");
    //gen_keys();
    let (public_keys, private_keys) = load_keys();
    let signatures = bench_sign(&private_keys);
    //bench_single_verify(&signatures, &public_keys);
    bench_agg(&signatures, &public_keys);
}

// Generate a million keys and write to file.
pub fn gen_keys()  -> io::Result<()> {
    let mut file = File::create("sigs_min_sig.txt")?;

    for _ in 0..1_000_000 {
        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let pvtKey = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pubKey = pvtKey.sk_to_pk();

        file.write_all(format!("{} {}\n", encode(pvtKey.to_bytes()), encode(pubKey.to_bytes())).as_bytes())?;
    }
    Ok(())
}

// Load keys from file.
pub fn load_keys() -> (Vec<PublicKey>, Vec<SecretKey>) {
    let file = File::open("../sigs_min_sig.txt").unwrap();
    let reader = io::BufReader::new(file);

    let mut privateKeys = Vec::new();
    let mut publicKeys = Vec::new();

    for line in reader.lines() {
        let line = line.unwrap();
        let content : Vec<_> = line.split(" ").collect();
        privateKeys.push(SecretKey::from_bytes(decode(content[0]).unwrap().as_ref()).unwrap());
        publicKeys.push(PublicKey::from_bytes(decode(content[1]).unwrap().as_ref()).unwrap());
        if privateKeys.len() >= 1_000_000 {
            break;
        }
    }
    (publicKeys, privateKeys)
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
    let mut agg_pubs = Vec::new();
    for size in [10,100,1000,10_000, 100_000, 1_000_000] {
        let subset: Vec<&_> = public_keys.iter().take(size).collect();
        let start = Instant::now();
        blst::min_sig::AggregatePublicKey::aggregate(&subset, false).unwrap();
        println!("Aggregating Public Keys {} times took: {:?}", size, start.elapsed());
        agg_pubs.push(subset);
    }

    let mut agg_sigs = Vec::new();
    for size in [10,100,1000,10_000, 100_000, 1_000_000] {
        let subset = &signatures.iter().take(size).collect::<Vec<_>>()[..];
        let start = Instant::now();
        agg_sigs.push(blst::min_sig::AggregateSignature::aggregate(&subset, false).unwrap());
        println!("Aggregating Signatures {} times took: {:?}", size, start.elapsed());
    }

    for (index, pubs) in agg_pubs.iter().enumerate() {
        let start = Instant::now();
        assert_eq!(agg_sigs[index].to_signature().fast_aggregate_verify(false, MSG, DST, &pubs), BLST_ERROR::BLST_SUCCESS);
        println!("Fast Aggregate Verify {} times took: {:?}", pubs.len(), start.elapsed());
    }
}