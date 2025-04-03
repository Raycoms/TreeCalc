
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

// Final cost for m=1024,d=2: network: 600ms computational: 806.8042831103999ms
// Final cost for m=512,d=2: network: 600ms computational: 401.51501370009595ms
// Final cost for m=256,d=3: network: 800ms computational: 354.94651030771195ms

//todo: Can we calculate a tree with varying fanout , smaller on top, bigger below. (Easy depth loop + check!)

//todo: This changes significantly if we
// a) Can do optimistic things (because we can punish misbehaving nodes) and
//      - This could also just be partially true (not on the lowest level, but indeed on the intermediate level).
// b) Do duplicates (larger agg cost).

//todo: Another question is optimistic handup. We can handup faster after some percentage (find formula again), but now we might have to merge things.

pub(crate) fn run() {

    // Final cost for m=1024,d=2: network: 600ms computational: 580.9045561337564ms
    // Final cost for m=700,d=2: network: 600ms computational: 434.0059643229953ms
    // Final cost for m=655,d=2: network: 600ms computational: 413.7551171342084ms
    // Final cost for m=600,d=3: network: 800ms computational: 486.2502332659575ms
    // Final cost for m=512,d=3: network: 800ms computational: 410.11593106749694ms
    // Final cost for m=400,d=3: network: 800ms computational: 328.8768199164956ms
    // Final cost for m=256,d=3: network: 800ms computational: 245.43317125836776ms
    // Final cost for m=128,d=5: network: 1200ms computational: 260.56298905439917ms
    // Final cost for m=64,d=7: network: 1600ms computational: 204.32735958187516ms
    // Final cost for m=1024,d=2: network: 600ms computational: 365.16258814139997ms

    calculate_cost(1024.0);
    calculate_cost(700.0);
    calculate_cost(655.0);

    calculate_cost(600.0);
    calculate_cost(512.0);

    calculate_cost(400.0);

    calculate_cost(256.0);

    calculate_cost(128.0);
    calculate_cost(64.0);


    calculate_cost_variable(1024.0, 4.0)

}

fn calculate_cost(m: f64) {
    // Round trip time
    let RTT = 200;

    // Duplication factor. Matters for aggregation time.
    let DUP_FACTOR = 1.0;

    // Number of cores for this.
    let C = 4.0;

    let VERIFYING_COST = 882.21440825 / 1000000.0 * 1000.0;
    let AGG_SIG_COST = 1.068981688 / 1000000.0 * 1000.0;
    let AGG_PUB_COST = 0.460724574 / 1000000.0 * 1000.0;

    let N = 1024.0 * 1024.0;

    let N1: f64 = N / m;
    let m1 = m / 16.0;

    let depth = N1.log(m1).ceil() as i32;

    // Total network latency
    let network_latency = RTT + RTT * depth;

    // Initial computation at the first set of nodes.
    let initial_comp = (VERIFYING_COST * m + AGG_PUB_COST * DUP_FACTOR * m + AGG_SIG_COST * DUP_FACTOR * m) / C;

    let mut tree_comp = 0.0;
    let mut nodes_left = N1;
    for i in 1..depth + 1 {
        // At the top of the tree, as we don't have a perfectly balanced tree, fanout might be smaller (this is good actually as it reduces leader load)
        let actual_fanout = m.min(nodes_left);
        tree_comp += (actual_fanout * 16 * VERIFYING_COST + actual_fanout * AGG_SIG_COST * DUP_FACTOR + N.min(m * m1.powi(i)) * AGG_PUB_COST * DUP_FACTOR) / C;
        //println!("{} {}", i, N.min(m*m1.powi(i)));
        nodes_left = nodes_left / m;
    }

    //println!("Final cost: network: {network_latency}ms computational: initial: {initial_comp}ms, tree comp: {tree_comp}ms");
    let total_comp = initial_comp + tree_comp;
    println!("Final cost for m={m},d={depth}: network: {network_latency}ms computational: {total_comp}ms");
    //println!("-----------------------------------------------------------------------------------------")
}

fn calculate_cost_variable(m: f64, reduction_factor: f64) {
    // Round trip time
    let RTT = 200;

    // Duplication factor. Matters for aggregation time.
    let DUP_FACTOR = 1.0;

    // Number of cores for this.
    let C = 4.0;

    let VERIFYING_COST = 882.21440825 / 1000000.0 * 1000.0;
    let AGG_SIG_COST = 1.068981688 / 1000000.0 * 1000.0;
    let AGG_PUB_COST = 0.460724574 / 1000000.0 * 1000.0;

    let N = 1024.0 * 1024.0;

    let N1: f64 = N / m;
    let m1 = m / 16.0;


    // We start with m and then we do m * 2 for next fanout until finished
    let initial_comp = (VERIFYING_COST * m + AGG_PUB_COST * DUP_FACTOR * m + AGG_SIG_COST * DUP_FACTOR * m) / C;
    let mut depth = 0;
    let mut tree_comp = 0.0;
    let mut variable_fanout = m1/ reduction_factor;
    let mut current_lower_nodes = N;
    let mut current_nodes = 1.0;

    loop {
        tree_comp += (variable_fanout * 16 * VERIFYING_COST + variable_fanout * AGG_SIG_COST * DUP_FACTOR + current_lower_nodes * AGG_PUB_COST * DUP_FACTOR) / C;
        current_lower_nodes = N/variable_fanout;
        variable_fanout = variable_fanout * 2.0;
        current_nodes = current_nodes * variable_fanout;
        depth = depth + 1;

        if current_nodes * m >= N {
            break;
        }
    }

    // Total network latency
    let network_latency = RTT + RTT * depth;

    //println!("Final cost: network: {network_latency}ms computational: initial: {initial_comp}ms, tree comp: {tree_comp}ms");
    let total_comp = initial_comp + tree_comp;
    println!("Final cost for m={m},d={depth}: network: {network_latency}ms computational: {total_comp}ms");
    //println!("-----------------------------------------------------------------------------------------")
}
