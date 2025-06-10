use std::collections::HashMap;
use std::sync::Arc;
use std::thread::{sleep};
use std::time::Duration;
use blst::byte;
use blst::min_pk::{PublicKey, SecretKey, Signature};
use tokio::task;
use hmac::{Mac};
use rand_core::RngCore;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use crate::simulation::main::{HmacSha256, DST};

pub struct Simulator {
    // Fanout.
    pub(crate) m: usize,
    // Proposal byte vector.
    pub proposal: Vec<byte>,
    pub leaf_channels: Vec<Sender<()>>,
    pub sibling_channels: Vec<Sender<()>>,
    pub parent_channels: Vec<Sender<()>>,
}

impl Default for Simulator {
    fn default() -> Self {
        Simulator {
            m: 312,
            proposal: Vec::new(),
            leaf_channels: Vec::new(),
            sibling_channels: Vec::new(),
            parent_channels: Vec::new(),
        }
    }
}

//TODO: Can we compress the massive set of public key thing? We got 2mb (megabit) for 2m nodes of just the public key. But for high participation rates we could compress this. Factor 50 as well?
// We could indicate ranges we have. Worst case adversary tries to corrupt every 3rd. So the range is useless though.
// Let's say we have 100k pure block data. We can use this for the proposal here for now. We could include the agg sig (minimal data) but we can have the set of public keys external.
// But overall, we would still receive this. We would just only sign the 100k of it.

// This is the simulator. At the moment is only does the second lowest level simulation.
// todo: Update in the future to run this as a full simulation.
//  missing: - Simulate 1 leaf node
//           - Simulate upper group parent
//           - Simulate tree of x-depth parents
//           - Simulate leader
//           -> Simulate x nodes in each group
//           -> Simulation in the bad case (first messages are the f bad ones, and we get a lot of the votes only from siblings etc).
impl Simulator {

    pub fn new(m: usize, proposal: &Vec<u8>) -> Self {
        Simulator {
            m,
            proposal: proposal.clone(),
            ..Default::default()
        }
    }

    // Prepare simulator. Open all necessary sockets and initiate signatures and public keys.
    pub async fn prepare(&mut self) -> Vec<Arc<PublicKey>> {

        // We set up connections for: Leaf nodes, siblings & parent nodes.

        // Leaf nodes will send out messages to their parent
        let (leaf_channels, pub_keys, port_to_sig_map) = setup_leaf_nodes(self, 10_000, self.m).await;
        self.leaf_channels.extend(leaf_channels);
        println!("Finished preparing Simulator leaf connections");

        let sibling_channels = setup_sibling_connection( 20_000, 127, port_to_sig_map, self.m).await;
        self.sibling_channels.extend(sibling_channels);
        println!("Finished preparing Simulator sibling connections");

        let parent_channels = setup_parent_connections( 30_000, 128).await;
        self.parent_channels.extend(parent_channels);
        println!("Finished preparing Simulator parent connections");

        // Sleep a sec and let the thread creation and listener creation finish.
        sleep(Duration::from_secs(1));

        Vec::from(pub_keys)
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {
        // Send out the leaf votes.
        for channel in self.leaf_channels.iter() {
            channel.send(()).await.unwrap();
        }

        // Send out the sibling votes.
        for channel in self.sibling_channels.iter() {
            channel.send(()).await.unwrap();
        }
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        for channel in self.leaf_channels.iter() {
            channel.send(()).await.unwrap();
        }
        for channel in self.sibling_channels.iter() {
            channel.send(()).await.unwrap();
        }
        for channel in self.parent_channels.iter() {
            channel.send(()).await.unwrap();
        }
    }
}

pub async fn setup_leaf_nodes(simulator: &mut Simulator, base_port : usize, range: usize) -> (Vec<Sender<()>>, Vec<Arc<PublicKey>>, HashMap<usize, Signature>) {
    let mut channels = Vec::new();
    let mut public_keys = Vec::new();
    let mut port_to_sig_map = HashMap::new();

    for i in 0..range {
        let port = base_port + i;
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await.unwrap();

        // Spawn a task to accept connections on this listener
        let (tx, mut rx) = mpsc::channel::<()>(2);
        channels.push(tx);

        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let pvt_key = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pub_key = pvt_key.sk_to_pk();
        public_keys.push(Arc::new(pub_key));

        let sig = pvt_key.sign(&simulator.proposal, DST, &[]);
        port_to_sig_map.insert(i, sig.clone());

        task::spawn(async move {
            println!("Listening on {}", addr);
            // We atm only need a single connection per port here (saves us from having a lot of async tasks doing nothing).
            match listener.accept().await {
                Ok((mut socket, addr)) => {
                    println!("New connection from {} on port {}", addr, port);
                    // Spawn a new task for each connection
                    rx.recv().await;
                    socket.write(&sig.to_bytes()).await.unwrap();

                    // Await second channel to close connection.
                    rx.recv().await;
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
    (channels, public_keys, port_to_sig_map)
}

pub async fn setup_sibling_connection(base_port : usize, range: usize, port_to_sig_map: HashMap<usize, Signature>, m: usize) -> Vec<Sender<()>> {
    let mut channels = Vec::new();

    for i in 0..range {
        let port = base_port + i;
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await.unwrap();
        println!("Listening on {}", addr);

        let (tx, mut rx) = mpsc::channel::<()>(2);
        channels.push(tx);

        // Spawn a task to accept connections on this listener

        let local_port_to_sig = port_to_sig_map.clone();
        task::spawn(async move {

            // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).
            match listener.accept().await {
                Ok((mut socket, addr)) => {
                    println!("New connection from {} on port {}", addr, port);
                    let port_string_bytes = port.to_string();
                    rx.recv().await;

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
                    rx.recv().await;
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
   channels
}

pub async fn setup_parent_connections(base_port : usize, range: usize) -> Vec<Sender<()>> {
    let mut channels = Vec::new();

    for i in 0..range {
        let port = base_port + i;
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await.unwrap();
        println!("Listening on {}", addr);

        let (tx, mut rx) = mpsc::channel::<()>(2);
        channels.push(tx);

        // Spawn a task to accept connections on this listener
        task::spawn(async move {
            // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).
            match listener.accept().await {
                Ok((socket, addr)) => {
                    println!("New connection from {} on port {}", addr, port);

                    // Wait before closing connection.
                    rx.recv().await;
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
    channels
}
