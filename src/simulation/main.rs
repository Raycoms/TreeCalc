use std::thread::sleep;
use std::time::{Duration, Instant};
use hmac::Hmac;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use crate::simulation::depth_based_internal_aggregator::DepthBasedInternalAggregator;
use crate::simulation::first_internal_aggregator::FirstInternalAggregator;
use crate::simulation::simulator::Simulator;
use crate::simulation::leaf_aggregator::LeafAggregator;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

// This is the simulator. At the moment is only does the second lowest level simulation.
// todo: Update in the future to run this as a full simulation.
//  missing: - Simulate 1 leaf node
//           - Simulate upper group parent
//           - Simulate tree of x-depth parents
//           - Simulate leader
//           -> Simulate x nodes in each group
//           -> Simulation in the bad case (first messages are the f bad ones, and we get a lot of the votes only from siblings etc).

pub(crate) async fn main() {

    // 2560000 (2.5m) Leaf nodes
    // 320 fanout
    // 6400 Leaf Aggregator Groups
    // 320 Internal Aggregator Groups
    // 20 Internal Aggregator Groups
    // 1 Leader


    // Fanout we're considering.
    let m = 320;
    let additional_depth = 2;

    // Set up simulator connections.

    // Random 100KB block data (about realistic).
    let mut proposal = vec![0u8; 100_000];
    OsRng.fill_bytes(&mut proposal);

    let mut simulator = Simulator::new(m, additional_depth, &proposal);
    let public_keys = simulator.open_connections().await;
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

    let mut leaf_aggregator = LeafAggregator::new(m, &proposal, public_keys.clone());
    leaf_aggregator.connect().await;

    first_internal_aggregator.connect().await;
    for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
        dep_based.connect().await;
    }
    // Send out network messages of simulator for the validator to process.
    simulator.run().await;
    println!("Started up Simulator");

    // Actually run the validator and measure time it took.
    let time_now = Instant::now();
    leaf_aggregator.run().await;
    println!("Now: {}", time_now.elapsed().as_millis());
    first_internal_aggregator.run().await;
    println!("Now 2: {}", time_now.elapsed().as_millis());
    for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
        dep_based.run().await;
    }

    // ----- Types of Roles: -----
    // Leaf node: Verifies initial proposal, signs it, and sends it out (TODO)
    //            - Each of the other aggregator types should also be a leaf aggregator and do the initial verification before starting the other work (started alongside the leaf aggregator) (TODO last)
    // Leaf aggregator: Collect leaf votes, aggregate and broadcast (done)
    // Internal aggregator: Collect aggregates from leaf aggregators, aggregate into 2 separate aggregate (largest & majority) and send up to next station (done)
    // -> Depth based needed still.
    // Leader aggregator. Collect aggregates from others and join 2 aggregates that we've gotten. (TODO)


    // Leaf sends to 128 parents, one of them is real (simulator only has to create 127 now, we create a new validatortype for this that listens to the m input.)

    // Give the program time to wrap up.
    sleep(Duration::from_secs(5));

    simulator.kill().await;
    leaf_aggregator.kill().await;
}