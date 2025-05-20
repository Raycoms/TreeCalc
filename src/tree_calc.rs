
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
    
    /*let N = 1024.0*1024.0*2.0;

    //todo binary search
    let mut best_config = (0,100000, 0);
    for i in 32..1024 {
        let (depth, cost) = calculate_cost_2(N, i as f64, false);
        if cost < best_config.1 {
           best_config = (depth, cost, i)
        }
    }

    let m = best_config.2;
    let depth = best_config.0;
    let total = best_config.1;
    println!("Final cost for m={m},d={depth}: total: {total}ms");*/

    calculate_cost_2(2097152.0, 312.0, false);
    calculate_cost_2(2097152.0, 312.0, true);

    // Final cost for m=312,d=3: total: 2238 - network: 800ms computational: 1438.8167779280739ms, probability: 0.00000003611039045559039
    // Final cost for m=512,d=3: total: 2324 - network: 800ms computational: 1524.133857952218ms, probability: 0.000000022004769340000507

    /*
    log_and_calculate_cost(N, 1024.0);
    log_and_calculate_cost(N, 700.0);
    log_and_calculate_cost(N, 655.0);

    log_and_calculate_cost(N, 600.0);
    log_and_calculate_cost(N, 512.0);

    log_and_calculate_cost(N, 400.0);

    log_and_calculate_cost(N, 256.0);
    log_and_calculate_cost(N, 200.0);
    */

    /*let mut best_config = (0,100000, 0,0.0);

    for i in 32..1024 {
        for factor in 10..1000 {
            let (depth, cost) = calculate_cost_variable(N, i as f64, factor as f64/10.0);
            if cost < best_config.1 {
                best_config = (depth, cost, i, factor as f64/10.0)
            }
        }
    }
    let m = best_config.2;
    let depth = best_config.0;
    let total = best_config.1;
    let factor = best_config.3;
    println!("Final cost for m={m},d={depth},factor{factor}: total: {total}ms");
    */

    //calculate_cost(128.0);
    //calculate_cost(64.0);

    // todo binary search?

    //calculate_cost_variable(64.0, 4.0);
    //calculate_cost_variable(128.0, 4.0);
    //calculate_cost_variable(265.0, 2.0);

    //calculate_cost_variable(64.0, 3.5);
    //calculate_cost_variable(128.0, 8.0);
    //calculate_cost_variable(265.0, 4.0);
}

fn log_and_calculate_cost(N: f64, m: f64) {
    let (depth, cost) = calculate_cost(N, m);
    println!("Final cost for m={m},d={depth}: total: {cost}ms");
}

fn log_and_calculate_cost_variable(N: f64, m: f64, growth_factor: f64) {
    let (depth, cost) = calculate_cost_variable(N, m, growth_factor);
    println!("Final cost for m={m},d={depth}: total: {cost}ms");
}

fn calculate_cost(N: f64, m: f64) -> (i32, i32) {
    // Round trip time
    let LATENCY = 200;

    // Number of cores for this.
    let C = 4.0;

    let VERIFYING_COST = 882.21440825 / 1000000.0 * 1000.0;
    let AGG_SIG_COST = 1.068981688 / 1000000.0 * 1000.0;
    let AGG_PUB_COST = 0.460724574 / 1000000.0 * 1000.0;

    let N1: f64 = N / m;
    let m1 = m / 16.0;

    let depth = N1.log(m1).ceil() as i32;

    // Total network latency
    let network_latency = LATENCY + LATENCY * depth;

    // Initial computation at the first set of nodes.
    let initial_comp = (VERIFYING_COST * m + AGG_PUB_COST * m + AGG_SIG_COST  * m) / C;

    let mut tree_comp = 0.0;
    let mut nodes_left = N1;
    for i in 1..depth + 1 {
        // At the top of the tree, as we don't have a perfectly balanced tree, fanout might be smaller (this is good actually as it reduces leader load)
        let actual_fanout = m1.min(nodes_left);
        tree_comp += (actual_fanout * 16.0 * VERIFYING_COST + actual_fanout * AGG_SIG_COST + N.min(m * m1.powi(i-1)) * actual_fanout * AGG_PUB_COST) / C;
        //println!("{} {}", i, N.min(m*m1.powi(i)));
        nodes_left = nodes_left / actual_fanout;
    }

    //println!("Final cost: network: {network_latency}ms computational: initial: {initial_comp}ms, tree comp: {tree_comp}ms");
    let total_comp = initial_comp + tree_comp;
    let total = total_comp as i32 + network_latency;

    //println!("Final cost for m={m},d={depth}: total: {total} - network: {network_latency}ms computational: {total_comp}ms");
    //println!("-----------------------------------------------------------------------------------------")
    (depth+1, total)
}

fn calculate_cost_variable(N: f64, m: f64, growth_factor: f64) -> (i32, i32) {
    // Round trip time
    let LATENCY = 200;

    // Number of cores for this.
    let C = 4.0;

    let VERIFYING_COST = 882.21440825 / 1000000.0 * 1000.0;
    let AGG_SIG_COST = 1.068981688 / 1000000.0 * 1000.0;
    let AGG_PUB_COST = 0.460724574 / 1000000.0 * 1000.0;

    let m1 = m / 16.0;

    // We start with m and then we do m * 2 for next fanout until finished
    let initial_comp = (VERIFYING_COST * m + AGG_PUB_COST * m + AGG_SIG_COST * m) / C;
    let mut depth = 0;
    let mut tree_comp = 0.0;
    let mut variable_fanout = m1 / growth_factor;
    let mut current_lower_nodes = N;
    let mut current_nodes = 1.0;

    loop {
        tree_comp += (variable_fanout * 16.0 * VERIFYING_COST + variable_fanout * AGG_SIG_COST + current_lower_nodes * AGG_PUB_COST) / C;
        current_lower_nodes = N/variable_fanout;
        variable_fanout = variable_fanout * growth_factor;
        current_nodes = current_nodes * variable_fanout;
        depth = depth + 1;

        if current_nodes * m >= N {
            break;
        }
    }

    // Total network latency
    let network_latency = LATENCY + LATENCY * depth;

    //println!("Final cost: network: {network_latency}ms computational: initial: {initial_comp}ms, tree comp: {tree_comp}ms");
    let total_comp = initial_comp + tree_comp;
    let total = total_comp as i32 + network_latency;
    //println!("Final cost for m={m},d={depth}: total: {total} - network: {network_latency}ms computational: {total_comp}ms ");
    //println!("-----------------------------------------------------------------------------------------")
    (depth+1, total)
}

// also add aggregate-verify as a trick (worst case x2 cost).
fn calculate_cost_2(N: f64, m: f64, tricks: bool) -> (i32, i32) {

    // Round trip time
    let LATENCY = 200;

    // Number of cores for this.
    let C = 4.0;

    // Previous block validation, let's assume 200ms, fixed cost.
    let BLOCK_VALIDATION_COST = 200.0;

    let VERIFYING_COST = 882.21440825 / 1000000.0 * 1000.0;
    let AGG_SIG_COST = 1.068981688 / 1000000.0 * 1000.0;
    let SINGLE_AGG_PUB_COST = 0.460724574 / 1000000.0 * 1000.0;

    let N1: f64 = N / m;
    let m1 = m / 16.0;

    let depth = N1.log(m1).ceil() as i32;

    // First the leave nodes verify the previous block signature, for this they will have to aggregate all public keys as well.

    let leaf_node_cost = calculate_n_agg_pub_cost(N, tricks, 2.0) / C + VERIFYING_COST + BLOCK_VALIDATION_COST;

    // Total network latency
    let network_latency = LATENCY + LATENCY * depth;

    // Initial computation at the first set of nodes.
    // Verify all signatures and build an aggregate.
    let initial_comp = (VERIFYING_COST * m + SINGLE_AGG_PUB_COST * m + AGG_SIG_COST * m) / C;

    let mut tree_comp = 0.0;
    let mut nodes_left = N1;

    let mut current_faulty_ratio : f64 = 2.0/3.0;

    let mut previous_nodes = m;
    for i in 1..depth {
        tree_comp += (m * VERIFYING_COST + m1 * AGG_SIG_COST * 2.0 + previous_nodes * SINGLE_AGG_PUB_COST * 2.0) / C;
        //println!("{} {}", i, N.min(m*m1.powi(i)));
        nodes_left = nodes_left / m1;
        previous_nodes = previous_nodes * m1;

        current_faulty_ratio = current_faulty_ratio - 1.0/6.0;
    }

    // At the top of the tree, as we don't have a perfectly balanced tree, fanout might be smaller (this is good actually as it reduces leader load)
    let final_fanout = m1.min(nodes_left.ceil());
    let leader_comp = (VERIFYING_COST * final_fanout * 16.0 + calculate_n_agg_pub_cost(N, tricks, 2.0) + AGG_SIG_COST * final_fanout * 16.0 * 2.0) / C;

    //println!("Final cost: network: {network_latency}ms computational: initial: {initial_comp}ms, tree comp: {tree_comp}ms");
    let total_comp = initial_comp + tree_comp + leader_comp + leaf_node_cost;
    let total = total_comp as i32 + network_latency;

    let partial_prob = (1.0 - current_faulty_ratio).powf(64.0);
    let failure_probability : f64 = 1.0-(1.0-partial_prob).powf(N1);
    println!("Final cost for m={m},d={depth}: total: {total} - network: {network_latency}ms computational: {total_comp}ms, probability: {failure_probability}");
    //println!("-----------------------------------------------------------------------------------------")
    (depth+1, total)
}

// Calculate the optimistic speedup with 99% participation rate.
// This could maybe also apply to the smaller aggregates if nodes are ordered (i.e. each group has the same 1..x, but just different leaders above).
fn calculate_n_agg_pub_cost(N: f64, tricks: bool, dup_factor: f64) -> f64 {
    let SINGLE_AGG_PUB_COST = 0.460724574 / 1000000.0 * 1000.0;
    if tricks {
        // Divided by 100
        // We only have to do the setup once, so it's x2 of the dup factor + once itself.
        let n_agg_cost = (N / 100.0) * SINGLE_AGG_PUB_COST;
        n_agg_cost * dup_factor + n_agg_cost
    }
    else {
        N * SINGLE_AGG_PUB_COST * dup_factor
    }
}
