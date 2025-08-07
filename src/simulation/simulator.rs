use crate::simulation::main::{HmacSha256, DST, PREPARE_POOL};
use bit_vec::BitVec;
use blst::byte;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use hmac::Mac;
use rand_core::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

pub struct Simulator {
    // Fanout.
    pub(crate) m: usize,
    // Total depth above leaf aggregator.
    pub depth: usize,
    // Total number of nodes.
    pub N: usize,
    // Divider of leader fanout.
    pub leader_divider: usize,
    // Proposal byte vector.
    pub proposal: Vec<byte>,
    pub leaf_channels: broadcast::Sender<()>,
    pub parent_channels: broadcast::Sender<()>,
    pub leaf_parent_channels: broadcast::Sender<()>,
    pub consensus_data: Arc<HashMap<usize, Vec<(PublicKey, Signature, BitVec)>>>,
    pub ip : String,
}

impl Simulator {
    pub fn new(m: usize, depth: usize, proposal: &Vec<u8>, leader_divider: usize, ip: &String) -> Self {
        let N = (m/16).pow( (depth + 1) as u32) * m / leader_divider;
        Simulator {
            m,
            depth,
            N,
            leader_divider,
            proposal: proposal.clone(),
            leaf_channels: broadcast::channel(2).0,
            parent_channels: broadcast::channel(2).0,
            leaf_parent_channels: broadcast::channel(2).0,
            consensus_data: Arc::new(HashMap::new()),
            ip: ip.clone(),
        }
    }

    pub async fn init(&mut self) -> (Vec<Arc<PublicKey>>, Signature, Signature, Arc<Vec<Signature>>) {
        // We set up connections for: Leaf nodes, siblings & parent nodes.
        let mut pub_keys = Vec::new();

        println!("Starting Simulator with {} {}", self.N, self.m);

        let (sender, mut receiver) = tokio::sync::mpsc::channel(self.N);
        for _ in 0..8 {
            let proposal_copy = self.proposal.clone();
            let share = self.N/8;
            let senderClone = sender.clone();
            PREPARE_POOL.spawn(async move {
                println!("Starting task with share: {}", share);
                for _ in 0..share {
                    let mut ikm = [0u8; 32];
                    {
                        let mut rng = rand::thread_rng();
                        rng.fill_bytes(&mut ikm);
                    }
                    let pvt_key = SecretKey::key_gen(&ikm, &[]).unwrap();
                    let pub_key = pvt_key.sk_to_pk();
                    senderClone.send((pub_key, pvt_key.sign(&proposal_copy, DST, &[]))).await.unwrap();
                }
                drop(senderClone);
            });
        }
        drop(sender);

        let mut sig_vec = Vec::new();
        while let Some((pub_key, sig)) = receiver.recv().await {
            pub_keys.push(Arc::new(pub_key));
            sig_vec.push(sig);
            if sig_vec.len() % 100_000 == 0 {
                println!("Got 100k Sigs, now at: {}", sig_vec.len());
            }
        }

        let sig_vec = Arc::new(sig_vec);

        println!("Finished Signatures, Starting Aggregation");

        // Map for agg per depth.
        let mut agg_map = HashMap::new();
        // Aggregate them into agg map.
        let mut agg_vec = Vec::new();

        let first_depth_size = self.N/self.m;
        let mut curr_index = 0;
        for _ in 0..first_depth_size {
            let mut curr_pub_ref_vec = Vec::new();
            let mut curr_sig_ref_vec = Vec::new();
            for _ in 0..self.m {
                curr_pub_ref_vec.push(pub_keys[curr_index].as_ref());
                curr_sig_ref_vec.push(&sig_vec[curr_index]);
                curr_index+=1;
            }
            let agg_pub = AggregatePublicKey::aggregate(&curr_pub_ref_vec, false).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&curr_sig_ref_vec, false).unwrap().to_signature();
            agg_vec.push((agg_pub, agg_sig, BitVec::from_elem(self.m, true)));
        }
        agg_map.insert(0, agg_vec);

        println!("Finished First Aggregation, Starting Recursive Aggregation");


        let mut map_idx = 0;
        println!("In map: {} {}", map_idx, agg_map.get(&0).unwrap().len());

        // Recursively build all levels of the tree.
        loop
        {
            let agg_vec = agg_map.get(&map_idx).unwrap();

            let mut local_agg_vec = Vec::new();

            let mut curr_pub_ref_vec = Vec::new();
            let mut curr_sig_ref_vec = Vec::new();
            let mut compound_bit_vec = BitVec::new();

            let mut divider = 1;
            if (map_idx + 1) == self.depth {
                divider = self.leader_divider;
            }

            for (pub_key, sig, bitvec) in agg_vec {
                curr_pub_ref_vec.push(pub_key);
                curr_sig_ref_vec.push(sig);

                compound_bit_vec.extend(bitvec);

                if curr_sig_ref_vec.len() == (self.m/16) {
                    let agg_pub = AggregatePublicKey::aggregate(&curr_pub_ref_vec, false).unwrap().to_public_key();
                    let agg_sig = AggregateSignature::aggregate(&curr_sig_ref_vec, false).unwrap().to_signature();

                    local_agg_vec.push((agg_pub, agg_sig, compound_bit_vec.clone()));

                    curr_sig_ref_vec.clear();
                    curr_sig_ref_vec.clear();
                    compound_bit_vec = BitVec::new();
                }
            }

            if local_agg_vec.len() <= 1 {
                break;
            }
            println!("In map: {} {} {}", map_idx+1, local_agg_vec.len(), divider);
            agg_map.insert(map_idx+1, local_agg_vec);
            map_idx+=1;
        }

        for i in agg_map.iter() {
            println!("In map: {} {}", i.0, i.1.len());
        }

        let mut sigs = Vec::new();
        for (pub_key, sig, bit_vec) in agg_map.get(&(agg_map.len()-1)).unwrap().iter() {
            sigs.push(sig);
        }

        let agg_sig = AggregateSignature::aggregate(&sigs, false).unwrap().to_signature();
        self.consensus_data = Arc::new(agg_map);

        println!("Finished Aggregation, Opening Connections");
        (Vec::from(pub_keys), agg_sig, sig_vec.get(0).unwrap().clone(), sig_vec)
    }

    pub async fn open_connections(&mut self, sig_vec: &Arc<Vec<Signature>>) {

        // Leaf nodes will send out messages to their parent
        setup_leaf_nodes(self, 10_000, self.m-1, sig_vec).await;
        println!("Finished preparing Simulator leaf connections");

        setup_parent_connections(self, 30_000, 127).await;
        println!("Finished preparing Simulator parent connections");

        for i in 1..self.depth {
            let base_port = 40_000 + 2000 * i;
            setup_parent_connections(self,base_port, 127).await;
        }

        println!("Finished Connections, sleeping for a sec");


        // Sleep a sec and let the thread creation and listener creation finish.
        sleep(Duration::from_secs(1));
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {
        // Send out the leaf votes.
        self.leaf_channels.send(()).unwrap();

        setup_leaf_parent_connections(self,11_000, self.m - 1).await;

        setup_children_connections(&self,30_000, self.m).await;

        for i in 0..self.depth {
            let base_port = 40_000 + 2000 * i;
            if i == 0 {
                setup_depth_children_connections(&self, base_port, self.m/self.leader_divider - 1, i, self.leader_divider).await;
            }
            else {
                setup_depth_children_connections(&self, base_port, self.m - 1, i, 1).await;
            }
        }
        println!("Finished connecting children to parent");
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        self.leaf_channels.send(()).unwrap();
        self.parent_channels.send(()).unwrap();
        self.leaf_parent_channels.send(()).unwrap();
    }
}

pub async fn setup_leaf_nodes(
    simulator: &mut Simulator,
    base_port: usize,
    range: usize,
    sigs: &Arc<Vec<Signature>>
) {
    for i in 1..(range+1) {
        let port = base_port + i;
        let addr = format!("{}:{}", simulator.ip, port);
        let listener = TcpListener::bind(&addr).await.unwrap();

        let mut rx = simulator.leaf_channels.subscribe();

        let clone = sigs.clone();
        // Spawn a task to accept connections on this listener
        PREPARE_POOL.spawn(async move {
            // We atm only need a single connection per port here (saves us from having a lot of async tasks doing nothing).
            match listener.accept().await {
                Ok((mut socket, addr)) => {
                    // Spawn a new task for each connection
                    rx.recv().await.unwrap();
                    socket.write(&clone[i].to_bytes()).await.unwrap();

                    // Await second channel to close connection.
                    rx.recv().await.unwrap();
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
}

pub async fn setup_parent_connections(
    simulator: &mut Simulator,
    base_port: usize,
    range: usize,
) {
    println!("Opening Ports: {} to {}", base_port + 1, base_port + range + 1);
    for i in 0..range {
        let port = base_port + i + 1;
        let addr = format!("{}:{}", simulator.ip, port);
        let listener = TcpListener::bind(&addr).await.unwrap();

        let mut rx = simulator.parent_channels.subscribe();

        // Spawn a task to accept connections on this listener
        PREPARE_POOL.spawn(async move {
            let listener = listener;

            // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).
            match listener.accept().await {
                Ok((socket, addr)) => {
                    // Wait before closing connection.
                    rx.recv().await.unwrap();
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
}

pub async fn setup_children_connections(simulator: &Simulator, base_port: usize, range: usize) {

    // We have m-1 connections. Each of them sends a signature aggregate. 20 distinct ones. The first one we already did!
    for i in 1..range {
        let port = base_port;
        let addr = format!("{}:{}", simulator.ip, port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();

        let data_copy = simulator.consensus_data.clone();

        let local_idx = i/16;

        PREPARE_POOL.spawn(async move {
            let copy = data_copy.get(&0).unwrap();
            let sub_copy = copy.get(local_idx);

            if sub_copy.is_none() {
                panic!("Couldn't find signature for child connection {}", i);
            }

            let port_string = port.to_string();
            let expected_mac = HmacSha256::new_from_slice(port_string.as_bytes());
            let mut unwrapped_mac = expected_mac.unwrap();

            let (pub_key, sig, bit_vec) = sub_copy.unwrap();
            unwrapped_mac.update(&sig.clone().to_bytes());

            stream.write(&local_idx.to_be_bytes()).await.unwrap();
            stream.write(&bit_vec.to_bytes()).await.unwrap();
            stream.write(&sig.to_bytes()).await.unwrap();
            stream.write(&unwrapped_mac.finalize().into_bytes()).await.unwrap();

        });
    }
}

pub async fn setup_leaf_parent_connections(simulator: &Simulator, base_port: usize, range: usize) {

    // We have m-1 connections. Each of them sends a signature aggregate. 20 distinct ones. The first one we already did!
    for i in 0..range {
        let port = base_port + i;
        let addr = format!("{}:{}", simulator.ip, port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();
        let mut rx = simulator.leaf_parent_channels.subscribe();

        PREPARE_POOL.spawn(async move {
            rx.recv().await.unwrap();
        });
    }
}

pub async fn setup_depth_children_connections(simulator: &Simulator, base_port: usize, range: usize, depth: usize, leader_divider: usize) {

    let reverse_idx = simulator.consensus_data.len() - depth - 1;

    for i in 1..(range+1) {
        let port = base_port;
        let addr = format!("{}:{}", simulator.ip, port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();

        let data_copy = simulator.consensus_data.clone();
        let local_idx = i/16;
        PREPARE_POOL.spawn(async move {
            let copy = data_copy.get(&reverse_idx).unwrap();
            let sub_copy = copy.get(local_idx);
            if sub_copy.is_none() {
                panic!("Couldn't find sig at depth {} {} {} {}", i, depth, reverse_idx, copy.len());
            }

            let port_string = port.to_string();
            let expected_mac = HmacSha256::new_from_slice(port_string.as_bytes());
            let mut unwrapped_mac = expected_mac.unwrap();

            let (pub_key, sig, bit_vec) = sub_copy.unwrap();
            unwrapped_mac.update(&sig.clone().to_bytes());

            stream.write(&local_idx.to_be_bytes()).await.unwrap();

            stream.write(&bit_vec.to_bytes()).await.unwrap();
            stream.write(&sig.to_bytes()).await.unwrap();

            stream.write(&bit_vec.to_bytes()).await.unwrap();
            stream.write(&sig.to_bytes()).await.unwrap();

            stream.write(&unwrapped_mac.finalize().into_bytes()).await.unwrap();
        });
    }
}
