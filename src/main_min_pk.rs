use std::fs::File;
use std::io;
use std::io::{BufRead, Write};
use std::time::Instant;
use blst::BLST_ERROR;
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_sig::{PublicKey, SecretKey, Signature};
use rand_core::RngCore;
use hex::encode;
use hex::decode;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
pub const MSG: &[u8] = b"blst is such a blast";

// Signing 1100000 times took: 156.5929778s
// Verifying 1100000 times took: 825.393036649s
// Aggregating Public Keys 10 times took: 13.034µs
// Aggregating Public Keys 100 times took: 112.951µs
// Aggregating Public Keys 1000 times took: 1.165445ms
// Aggregating Public Keys 10000 times took: 11.718669ms
// Aggregating Public Keys 100000 times took: 118.301585ms
// Aggregating Public Keys 1000000 times took: 1.165605514s
// Aggregating Signatures 10 times took: 7.023µs
// Aggregating Signatures 100 times took: 45.094µs
// Aggregating Signatures 1000 times took: 458.666µs
// Aggregating Signatures 10000 times took: 4.628958ms
// Aggregating Signatures 100000 times took: 46.335256ms
// Aggregating Signatures 1000000 times took: 463.512725ms

fn main() {
    println!("Hello, world!");
    let (public_keys, private_keys) = load_keys();
    let signatures = bench_sign(&private_keys);
    //bench_single_verify(&signatures, &public_keys);
    bench_agg(&signatures, &public_keys);
}

// Generate a million keys and write to file.
pub fn gen_keys()  -> std::io::Result<()> {
    let mut file = File::create("sigs.txt")?;

    for i in 0..1_000_000 {
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
    let file = File::open("sigs.txt").unwrap();
    let reader = io::BufReader::new(file);

    let mut privateKeys = Vec::new();
    let mut publicKeys = Vec::new();

    for line in reader.lines() {
        let line = line.unwrap();
        let content : Vec<_> = line.split(" ").collect();
        privateKeys.push(SecretKey::from_bytes(decode(content[0]).unwrap().as_ref()).unwrap());
        publicKeys.push(PublicKey::from_bytes(decode(content[1]).unwrap().as_ref()).unwrap());
        if (privateKeys.len() >= 1_000_000) {
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
    for size in [10,100,1000,10_000, 100_000, 1_000_000] {
        let subset = &public_keys.iter().take(size).collect::<Vec<_>>()[..];
        let start = Instant::now();
        let agg_pub = blst::min_sig::AggregatePublicKey::aggregate(&subset, false).unwrap();
        println!("Aggregating Public Keys {} times took: {:?}", size, start.elapsed());
    }

    for size in [10,100,1000,10_000, 100_000, 1_000_000] {
        let subset = &signatures.iter().take(size).collect::<Vec<_>>()[..];
        let start = Instant::now();
        let agg_sig = blst::min_sig::AggregateSignature::aggregate(&subset, false).unwrap();
        println!("Aggregating Signatures {} times took: {:?}", size, start.elapsed());
    }
}

pub fn test_bls(){
    let mut sumSignElapsed = 0;
    let mut sumTotalElapsed = 0;
    let mut sumAggPub = 0;
    let mut sumAggSig = 0;

    let settings = [10, 25, 100, 500];

    for k in settings {
        for i in 0..100 {
            let mut rng = rand::thread_rng();
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);

            let mut privateKeys = vec![];
            let mut publicKeys = vec![];

            for n in 0..k {
                let pvtKey = SecretKey::key_gen(&ikm, &[]).unwrap();
                let pubKey = pvtKey.sk_to_pk();
                privateKeys.push((pvtKey, pubKey));
                publicKeys.push(pubKey);
            }

            let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
            let msg = b"blst is such a blast";

            let start = Instant::now();
            let mut signatures = vec![];
            for (pvtKey, pubKey) in &privateKeys {
                signatures.push(pvtKey.sign(msg, dst, &[]));
            }
            sumSignElapsed += start.elapsed().as_micros();

            let start2 = Instant::now();
            let pks_rev: Vec<&blst::min_sig::PublicKey> =
                publicKeys.iter().rev().map(|pk| pk).collect();

            let aggPub = blst::min_sig::AggregatePublicKey::aggregate(&pks_rev, false).unwrap();

            sumAggPub += start2.elapsed().as_micros();

            let start3 = Instant::now();
            let sig_refs_i =
                signatures.iter().map(|s| s).collect::<Vec<&blst::min_sig::Signature>>();

            let aggSig = blst::min_sig::AggregateSignature::aggregate(&sig_refs_i, false).unwrap();
            sumAggSig += start3.elapsed().as_micros();

            let start4 = Instant::now();
            // Check whether the aggregate signature corresponds to the aggregated
            // public_key

            // We don't have to do the group check as we should do that on accepting a peer
            // todo: Before a new peer is added, we do a public key group check to make sure we don't get maliciously constructed ones.
            assert_eq!(aggSig.to_signature().fast_aggregate_verify(false, msg, dst, &pks_rev), BLST_ERROR::BLST_SUCCESS);

            sumTotalElapsed += start4.elapsed().as_micros();
        }

        println!("Elapsed {} bls: {} {} {} {}", k, sumSignElapsed/100/k, sumAggPub/100, sumAggSig/100, sumTotalElapsed/100);
    }
}

pub fn aggregate_verify2<T : AsRef<[u8]>>(sigs: &Vec<Signature>, pks_rev: &Vec<&PublicKey>, msg: T, x: &Vec<PublicKey>) -> (blst::min_sig::AggregateSignature, blst::min_sig::AggregatePublicKey, bool, Vec<usize>){
    let sig_refs =
        sigs.iter().map(|s| s).collect::<Vec<&Signature>>();

    let agg_pub = blst::min_sig::AggregatePublicKey::aggregate(&pks_rev, false).unwrap();
    let agg_sig = blst::min_sig::AggregateSignature::aggregate(&sig_refs, false).unwrap();

    let res = agg_sig.to_signature().verify(true, msg.as_ref(), DST, &[], &agg_pub.to_public_key(), false);
    if (res.eq(&BLST_SUCCESS))
    {
        return (agg_sig, agg_pub, true, vec![])
    }

    let mut new_pks_rev = vec![];
    let mut new_sigs_rev = vec![];
    let mut wrong_sigs = vec![];

    for (i, sig) in sigs.iter().enumerate()
    {
        let temp_res = sig.verify(true, msg.as_ref(), DST, &[], &x[i], false);
        if (temp_res.eq(&BLST_SUCCESS))
        {
            new_pks_rev.push(pks_rev[i]);
            new_sigs_rev.push(sig);
        }
        else
        {
            wrong_sigs.push(i);
        }
    }


    let new_agg_pub = blst::min_sig::AggregatePublicKey::aggregate(&new_pks_rev, false).unwrap();
    let new_agg_sig = blst::min_sig::AggregateSignature::aggregate(&new_sigs_rev, false).unwrap();

    let new_res = new_agg_sig.to_signature().verify(true, msg.as_ref(), DST, &[], &new_agg_pub.to_public_key(), false);
    if (new_res.eq(&BLST_SUCCESS))
    {
        return (agg_sig, agg_pub, true, wrong_sigs)
    }

    return (agg_sig, agg_pub, false, wrong_sigs)
}