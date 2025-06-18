use crate::simulation::main::{HmacSha256, DST};
use bit_vec::BitVec;
use blst::byte;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR::BLST_SUCCESS;
use hmac::Mac;
use rand_core::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use futures::SinkExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::task;

pub struct Simulator {
    // Fanout.
    pub(crate) m: usize,
    // Total depth above leaf aggregator.
    pub depth: usize,
    // Total number of nodes.
    pub N: usize,
    // Proposal byte vector.
    pub proposal: Vec<byte>,
    pub leaf_channels: broadcast::Sender<()>,
    pub sibling_channels: broadcast::Sender<()>,
    pub parent_channels: broadcast::Sender<()>,
    pub consensus_data: Arc<HashMap<usize, Vec<(PublicKey, Signature, BitVec)>>>,
}

impl Simulator {
    pub fn new(m: usize, depth: usize, proposal: &Vec<u8>) -> Self {
        let N = (m/16)^(depth+1)*m;
        Simulator {
            m,
            depth,
            N,
            proposal: proposal.clone(),
            leaf_channels: broadcast::channel(2).0,
            sibling_channels: broadcast::channel(2).0,
            parent_channels: broadcast::channel(2).0,
            consensus_data: Arc::new(HashMap::new()),
        }
    }

    pub async fn open_connections(&mut self) -> Vec<Arc<PublicKey>> {
        // We set up connections for: Leaf nodes, siblings & parent nodes.

        // Leaf nodes will send out messages to their parent
        let (mut pub_keys, port_to_sig_map) = setup_leaf_nodes(self, 10_000, self.m).await;
        println!("Finished preparing Simulator leaf connections");

        setup_sibling_connection(20_000, 127, port_to_sig_map.clone(), self.m, &mut self.sibling_channels).await;
        println!("Finished preparing Simulator sibling connections");

        setup_parent_connections(30_000, 127, &mut self.parent_channels).await;
        println!("Finished preparing Simulator parent connections");

        let public_key_refs: Vec<&PublicKey> = pub_keys.iter().map(|pk| pk.as_ref()).collect();
        let sig_refs: Vec<&Signature> = port_to_sig_map.iter().map(|(_, sig)| sig).collect();

        let agg_pub = AggregatePublicKey::aggregate(&public_key_refs, false);
        let bit_vec = BitVec::from_elem(self.m, true);
        let agg_sig = AggregateSignature::aggregate(&sig_refs, false);

        if !agg_sig.unwrap().to_signature().verify(false, &self.proposal, DST, &[], &agg_pub.unwrap().to_public_key(), false, ).eq(&BLST_SUCCESS)  {
            panic!("Unable to verify agg signature");
        }

        let mut local_consensus_data = Vec::new();
        local_consensus_data.push((0, agg_pub.unwrap().to_public_key(), agg_sig.unwrap().to_signature(), bit_vec,));

        let (sender, mut receiver) = tokio::sync::mpsc::channel(self.N);
        for _ in 0..8 {
            let proposal_copy = self.proposal.clone();
            let share = self.N/8;
            let senderClone = sender.clone();
            tokio::spawn(async move {
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
            });
        }

        let mut sig_vec = Vec::new();
        while let Some((pub_key, sig)) = receiver.recv().await {
            pub_keys.push(Arc::new(pub_key));
            sig_vec.push(sig);
        }

        // Map for agg per depth.
        let mut agg_map = HashMap::new();
        // Aggregate them into agg map.
        let mut agg_vec = Vec::new();

        let first_depth_size = self.N/self.m;
        let mut curr_pub_idx = pub_keys.len();
        let mut curr_sig_idx = 0;
        for _ in 0..first_depth_size {
            let mut curr_pub_ref_vec = Vec::new();
            let mut curr_sig_ref_vec = Vec::new();
            for _ in 0..self.m {
                curr_pub_ref_vec.push(pub_keys[curr_pub_idx].as_ref());
                curr_sig_ref_vec.push(&sig_vec[curr_sig_idx]);

                curr_pub_idx+=1;
                curr_sig_idx+=1;
            }
            let agg_pub = AggregatePublicKey::aggregate(&curr_pub_ref_vec, false).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&curr_sig_ref_vec, false).unwrap().to_signature();
            agg_vec.push((agg_pub, agg_sig, BitVec::from_elem(self.m, true)));
        }
        agg_map.insert(0, agg_vec);

        let map_idx = 0;

        // Recursively build all levels of the tree.
        loop
        {
            let agg_vec = agg_map.get(&map_idx).unwrap();
            if agg_vec.len() == 1 {
                break;
            }
            let mut local_agg_vec = Vec::new();

            let mut curr_pub_ref_vec = Vec::new();
            let mut curr_sig_ref_vec = Vec::new();
            let mut compound_bit_vec = BitVec::new();
            for (pub_key, sig, bitvec) in agg_vec {
                curr_pub_ref_vec.push(pub_key);
                curr_sig_ref_vec.push(sig);

                compound_bit_vec.extend(bitvec);
            }
            let agg_pub = AggregatePublicKey::aggregate(&curr_pub_ref_vec, false).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&curr_sig_ref_vec, false).unwrap().to_signature();
            local_agg_vec.push((agg_pub, agg_sig, compound_bit_vec));
            agg_map.insert(curr_pub_idx+1, local_agg_vec);
            curr_pub_idx+=1;
        }

        self.consensus_data = Arc::new(agg_map);

        for i in 0..self.depth {
            let base_port = 40_000 + 1000 * i;
            setup_parent_connections(base_port, 127, &mut self.parent_channels).await;
        }

        // Sleep a sec and let the thread creation and listener creation finish.
        sleep(Duration::from_secs(1));

        Vec::from(pub_keys)
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {
        // Send out the leaf votes.
        self.leaf_channels.send(()).unwrap();

        // Send out the sibling votes.
        self.sibling_channels.send(()).unwrap();

        setup_children_connections(&self,30_000, self.m - 1).await;

        for i in 0..self.depth {
            let base_port = 40_000 + 1000 * i;
            setup_depth_children_connections(&self, base_port, self.m - 1, i).await;
        }
        println!("Finished connecting children to parent");
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        self.leaf_channels.send(()).unwrap();
        self.sibling_channels.send(()).unwrap();
        self.parent_channels.send(()).unwrap();
    }
}

pub async fn setup_leaf_nodes(
    simulator: &mut Simulator,
    base_port: usize,
    range: usize,
) -> (Vec<Arc<PublicKey>>, HashMap<usize, Signature>) {
    let mut public_keys = Vec::new();
    let mut port_to_sig_map = HashMap::new();

    for i in 0..range {
        let port = base_port + i;
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await.unwrap();

        let mut rx = simulator.leaf_channels.subscribe();

        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let pvt_key = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pub_key = pvt_key.sk_to_pk();
        public_keys.push(Arc::new(pub_key));

        let sig = pvt_key.sign(&simulator.proposal, DST, &[]);
        port_to_sig_map.insert(i, sig.clone());

        // Spawn a task to accept connections on this listener
        task::spawn(async move {
            // We atm only need a single connection per port here (saves us from having a lot of async tasks doing nothing).
            match listener.accept().await {
                Ok((mut socket, addr)) => {
                    // Spawn a new task for each connection
                    rx.recv().await.unwrap();
                    socket.write(&sig.to_bytes()).await.unwrap();

                    // Await second channel to close connection.
                    rx.recv().await.unwrap();
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
    (public_keys, port_to_sig_map)
}

pub async fn setup_sibling_connection(
    base_port: usize,
    range: usize,
    port_to_sig_map: HashMap<usize, Signature>,
    m: usize,
    sender: &broadcast::Sender<()>,
) {
    for i in 0..range {
        let port = base_port + i + 1;
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await.unwrap();

        let mut rx = sender.subscribe();

        // Spawn a task to accept connections on this listener
        let local_port_to_sig = port_to_sig_map.clone();
        task::spawn(async move {
            // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).
            match listener.accept().await {
                Ok((mut socket, addr)) => {
                    let port_string_bytes = port.to_string();
                    rx.recv().await.unwrap();

                    for j in 0..m {
                        let id = j;

                        let sig = local_port_to_sig.get(&id).unwrap();
                        let sig_bytes = sig.to_bytes();

                        let mut mac = HmacSha256::new_from_slice(port_string_bytes.as_bytes());
                        let mut unwrapped_mac = mac.unwrap();
                        unwrapped_mac.update(&sig_bytes);
                        let vote = unwrapped_mac.finalize().into_bytes();

                        // Send MAC
                        socket.write(&vote.to_vec()).await.unwrap();

                        socket.write(&j.to_be_bytes()).await.unwrap();

                        // Send vote
                        socket.write(&sig_bytes).await.unwrap();
                    }

                    // keep channel open to receive the sibling broadcast.
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
    base_port: usize,
    range: usize,
    sender: &broadcast::Sender<()>,
) {
    println!("Opening Ports: {} to {}", base_port + 1, base_port + range + 1);
    for i in 0..range {
        let port = base_port + i + 1;
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await.unwrap();

        let mut rx = sender.subscribe();

        // Spawn a task to accept connections on this listener
        task::spawn(async move {
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
    for i in 0..range {
        let port = base_port;
        let addr = format!("127.0.0.1:{}", port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();

        let data_copy = simulator.consensus_data.clone();
        let local_idx = i%20;

        task::spawn(async move {
            let copy = data_copy.get(&0).unwrap();
            let sub_copy = copy.get(local_idx);

            if sub_copy.is_none() {
                panic!("awath {}", i);
            }

            let port_string = port.to_string();
            let expected_mac = HmacSha256::new_from_slice(port_string.as_bytes());
            let mut unwrapped_mac = expected_mac.unwrap();

            let idx = i%20;
            let (pub_key, sig, bit_vec) = sub_copy.unwrap();
            unwrapped_mac.update(&sig.clone().to_bytes());

            stream.write(&idx.to_be_bytes()).await.unwrap();
            stream.write(&bit_vec.to_bytes()).await.unwrap();
            stream.write(&sig.to_bytes()).await.unwrap();
            stream.write(&unwrapped_mac.finalize().into_bytes()).await.unwrap();

        });
    }
}

pub async fn setup_depth_children_connections(simulator: &Simulator, base_port: usize, range: usize, depth: usize) {

    let reverse_idx = simulator.consensus_data.len() - depth - 1;

    for i in 0..range {
        let port = base_port;
        let addr = format!("127.0.0.1:{}", port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();

        let data_copy = simulator.consensus_data.clone();
        let local_idx = i%20;

        task::spawn(async move {
            let copy = data_copy.get(&reverse_idx).unwrap();
            let sub_copy = copy.get(local_idx);
            if sub_copy.is_none() {
                panic!("awath {}", i);
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
