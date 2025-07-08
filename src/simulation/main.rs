use std::thread::sleep;
use std::time::{Duration, Instant};
use hmac::Hmac;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use crate::simulation::depth_based_internal_aggregator::DepthBasedInternalAggregator;
use crate::simulation::first_internal_aggregator::FirstInternalAggregator;
use crate::simulation::simulator::Simulator;
use crate::simulation::leaf_aggregator::LeafAggregator;
use crate::simulation::leaf_node::LeafNode;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

pub(crate) async fn main() {

    // 2560000 (2.5m) Leaf nodes
    // 320 fanout
    // 6400 Leaf Aggregator Groups
    // 320 Internal Aggregator Groups
    // 20 Internal Aggregator Groups
    // 1 Leader

    // Multiple Worst Cases
    // -> Worst case 1/3 faulty
    // -> Worst case, bad group distributions under the 1/3 and last one we check
    // -----> In the presence of 1/3, on average.


    // Fanout we're considering.
    let m = 320;
    let additional_depth = 2;

    // Set up simulator connections.

    // Random 100KB block data (about realistic).
    let mut proposal = vec![0u8; 100_000];
    OsRng.fill_bytes(&mut proposal);

    let mut simulator = Simulator::new(m, additional_depth, &proposal);
    let (public_keys, agg_sig, my_sig) = simulator.open_connections().await;
    println!("Finished preparing Simulator");

    let mut depth_based_internal_aggregator_vec = Vec::new();

    for i in (0..additional_depth).rev() {
        depth_based_internal_aggregator_vec.push(DepthBasedInternalAggregator::new(m, i, additional_depth, &proposal, public_keys.clone()));
    }

    // Set up validator connections.
    let mut first_internal_aggregator = FirstInternalAggregator::new(m, additional_depth, &proposal, public_keys.clone());
    first_internal_aggregator.open_connections().await;
    for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
        dep_based.open_connections().await;
    }

    let mut leaf_node = LeafNode::new(m, &proposal, public_keys.clone(), my_sig, agg_sig);
    leaf_node.connect().await;

    // 200ms network

    let mut leaf_aggregator = LeafAggregator::new(m, &proposal, public_keys.clone());

    // 200ms broadcast
    leaf_aggregator.connect().await;

    // 200ms network

    first_internal_aggregator.connect().await;
    for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
        dep_based.connect().await;
    }

    // 200ms network

    // Send out network messages of simulator for the validator to process.
    simulator.run().await;
    println!("Started up Simulator");

    // Actually run the validator and measure time it took.
    let time_now = Instant::now();
    leaf_node.run().await;
    println!("Now 1: {}", time_now.elapsed().as_millis());
    leaf_aggregator.run().await;
    println!("Now 2: {}", time_now.elapsed().as_millis());
    first_internal_aggregator.run().await;
    println!("Now 3: {}", time_now.elapsed().as_millis());
    for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
        dep_based.run().await;
        println!("Now 4x: {}", time_now.elapsed().as_millis());
    }


    // ----- Types of Roles: -----
    // Leaf node: Verifies initial proposal, signs it, and sends sig out (done)
    // Leaf aggregator: Collect leaf votes, aggregate and broadcast (done)
    // Internal aggregator: Collect aggregates from leaf aggregators, aggregate into 2 separate aggregate (largest & majority) and send up to next station (done)
    // Leader aggregator. Collect aggregates from others and join 2 aggregates that we've gotten. (done)

    // Leaf sends to 128 parents, one of them is real (simulator only has to create 127 now, we create a new validatortype for this that listens to the m input.)

    //todo ethereum might've adjusted to weighted voting?

    //todo: atm they all do public key aggregates for all 20 different groups, this is suuuuuper expensive.
    //todo: Can we do sth about this? Think?

    //todo: Simulate average 1/3 byz case

    //todo: On highest level we might want to have signatures and not Macs. As verify cost < agg pub cost.

    // Do group by group. Try to find the one that is correct. This is quite fast we can do at least "a few groups".
    // The leader can verify the rest and send it to the next leader to have them include it.
    // Next leader only accepts if threshold was not met in the previous block. Slighy overhead but at least we guarantee finality. Becomes then 4 slot finality.
    // Proof of misbehaviour was sent around as well, so people were slashed for doing this.

    // If we only have to do once the public key agg, we're better off. But in the worst case? ugh?

    // Give the program time to wrap up.
    sleep(Duration::from_secs(5));

    simulator.kill().await;
    leaf_aggregator.kill().await;
}