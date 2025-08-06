use std::thread::sleep;
use std::time::{Duration, Instant};
use hmac::Hmac;
use once_cell::sync::Lazy;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use tokio::runtime::{Builder, Runtime};
use crate::simulation::depth_based_internal_aggregator::DepthBasedInternalAggregator;
use crate::simulation::first_internal_aggregator::FirstInternalAggregator;
use crate::simulation::simulator::Simulator;
use crate::simulation::leaf_aggregator::LeafAggregator;
use crate::simulation::leaf_node::LeafNode;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

// Thread pool 1: 4 threads
pub(crate) static RUN_POOL: Lazy<Runtime> = Lazy::new(|| {
    Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("run")
        .enable_all()
        .build()
        .unwrap()
});

// Thread pool 2: 4 threads
pub(crate) static PREPARE_POOL: Lazy<Runtime> = Lazy::new(|| {
    Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("run")
        .enable_all()
        .build()
        .unwrap()
});


pub(crate) async fn main() {

    //todo optimization:
    // -> Leaf nodes cache public key aggregate and subtract!

    // 2560000 (2.5m) Leaf nodes
    // 320 fanout
    // 8000 Leaf Aggregator Groups
    // 400 Internal Aggregator Groups
    // 20 Internal Aggregator Groups
    // 1 Leader

    // Multiple Worst Cases
    // -> Worst case 1/3 faulty
    // -> Worst case, bad group distributions under the 1/3 and last one we check
    // -----> In the presence of 1/3, on average.

    // Fanout we're considering.
    let m = 256;
    let additional_depth = 2;
    let leader_divider = 1;

    // Set up simulator connections.

    // Random 100KB block data (about realistic).
    let mut proposal = vec![0u8; 100_000];
    OsRng.fill_bytes(&mut proposal);

    let mut simulator = Simulator::new(m, additional_depth, &proposal, leader_divider);
    let (public_keys, agg_sig, my_sig, sig_vec) = simulator.init().await;

    let mut final_time = 0;
    for _ in 0..10 {
        simulator.open_connections(&sig_vec).await;
        println!("Finished preparing Simulator");

        let mut depth_based_internal_aggregator_vec = Vec::new();

        for i in (0..additional_depth).rev() {
            let mut internal_leader_divider = 1;
            if i == 0 {
                internal_leader_divider = leader_divider;
            }
            depth_based_internal_aggregator_vec.push(DepthBasedInternalAggregator::new(m, i, additional_depth, &proposal, public_keys.clone(), internal_leader_divider));
        }

        // Set up validator connections.
        let mut first_internal_aggregator = FirstInternalAggregator::new(m, additional_depth, &proposal, public_keys.clone());
        first_internal_aggregator.open_connections().await;
        for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
            dep_based.open_connections().await;
        }

        let mut leaf_node = LeafNode::new(m, &proposal, public_keys.clone(), my_sig, agg_sig);
        leaf_node.connect().await;

        let mut network = 200;

        let mut leaf_aggregator = LeafAggregator::new(m, &proposal, public_keys.clone());

        leaf_aggregator.connect().await;

        // 200ms network
        network += 200;

        first_internal_aggregator.connect().await;
        for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
            dep_based.connect().await;

            // 200ms network
            network += 200;
        }

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

        let time_final = time_now.elapsed().as_millis() + network;

        final_time+=time_final;

        println!("Time final: {}", time_final);

        // ----- Types of Roles: -----
        // Leaf node: Verifies initial proposal, signs it, and sends sig out (done)
        // Leaf aggregator: Collect leaf votes, aggregate and broadcast (done)
        // Internal aggregator: Collect aggregates from leaf aggregators, aggregate into 2 separate aggregate (largest & majority) and send up to next station (done)
        // Leader aggregator. Collect aggregates from others and join 2 aggregates that we've gotten. (done)

        // Leaf sends to 128 parents, one of them is real (simulator only has to create 127 now, we create a new validatortype for this that listens to the m input.)

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
        first_internal_aggregator.kill().await;
        for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
            dep_based.kill().await;
        }
    }

    let result = final_time/10;
    println!("Result final: {}", result);
}