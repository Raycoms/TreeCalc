use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{PublicKey, SecretKey, Signature};
use dashmap::{DashMap};
use hmac::Mac;
use rand_core::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::simulation::main::{HmacSha256, DST};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task;

pub struct Validator {
    // Fanout.
    pub(crate) m: usize,
    // Proposal byte vector.
    pub proposal: Arc<Vec<byte>>,
    pub public_key: PublicKey,
    pub private_key: SecretKey,
    pub leaf_channels: Vec<Sender<()>>,
    pub sibling_channels: Vec<(Sender<()>, Sender<()>)>,
    pub parent_channels: Vec<Sender<()>>,
    pub public_keys: Arc<Vec<PublicKey>>,
    pub signature_map: Arc<DashMap<usize, Signature>>
}

impl Default for Validator {
    fn default() -> Self {
        Validator {
            m: 312,
            public_key: PublicKey::default(),
            private_key: SecretKey::default(),
            proposal: Arc::new(Vec::new()),
            leaf_channels: Vec::new(),
            sibling_channels: Vec::new(),
            parent_channels: Vec::new(),
            public_keys: Arc::new(Vec::new()),
            signature_map: Arc::new(DashMap::new()),
        }
    }
}

impl Validator {

    pub fn new(m: usize, proposal: &Vec<u8>, public_keys: Vec<PublicKey>) -> Self {
        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let private_key = SecretKey::key_gen(&ikm, &[]).unwrap();
        let public_key = private_key.sk_to_pk();

        Validator {
            m,
            public_key,
            private_key,
            proposal: Arc::new(proposal.clone()),
            public_keys: Arc::new(public_keys),
            ..Default::default()
        }
    }

    // Prepare simulator. Open all necessary sockets and initiate signatures and public keys.
    pub async fn prepare(&mut self) {

        // We set up connections for: Leaf nodes, siblings & parent nodes.

        // Signature processing channel. todo move to constructor, those need to stay alive.
        let (mut signature_sender, mut signature_receiver) = mpsc::channel(self.m);

        // Leaf nodes will send out messages to their parent
        let (leaf_channels) = connect_to_leaf_nodes( 10_000, self.m, signature_sender).await;
        self.leaf_channels.extend(leaf_channels);
        println!("Finished preparing Validator leaf connections");


        let (mut sibling_signature_sender, mut sibling_signature_receiver) = mpsc::channel(self.m * 128);

        let (mut sibling_signature_sender2, mut sibling_signature_receiver2) = mpsc::channel(self.m * 128);

        let sibling_channels = setup_sibling_connection(20_000, 127, sibling_signature_sender, sibling_signature_receiver2, self.m).await;
        self.sibling_channels.extend(sibling_channels);
        println!("Finished preparing Validator sibling connections");

        // So we could verify them all independently.
        let proposal = self.proposal.clone();

        //todo: We want to do this in parallel for c-cores in the future.
        let leaf_sig_map_copy = self.signature_map.clone();
        let local_public_keys = self.public_keys.clone();
        tokio::spawn(async move {
            while let Some((id, sig)) = signature_receiver.recv().await {
                if sig.verify(false, &proposal, DST, &[], local_public_keys.get(id).unwrap(), false).eq(&BLST_SUCCESS) {
                    if leaf_sig_map_copy.insert(id.clone(), sig.clone()).is_none() {
                        let _ = sibling_signature_sender2.send((id, sig)).await;
                    }
                } else {
                    println!("Got wrong signature from leaf.");
                }
            }
        });

        let proposal2 = self.proposal.clone();
        let sibling_sig_map_copy = self.signature_map.clone();
        let local_public_keys2 = self.public_keys.clone();
        tokio::spawn(async move {
            while let Some((id, sig)) = sibling_signature_receiver.recv().await {
                if !sibling_sig_map_copy.contains_key(&id) {
                    if sig.verify(false, &proposal2, DST, &[], local_public_keys2.get(id).unwrap(), false).eq(&BLST_SUCCESS) {
                        sibling_sig_map_copy.insert(id.clone(), sig.clone());
                    } else {
                        println!("Got wrong signature from sibling.");
                    }
                }
            }
        });

        //todo send aggregate to parents and notify run thread once it's done.
        //let parent_channels = setup_parent_connections(30_000, 128).await;
        //self.parent_channels.extend(parent_channels);
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {
        // Send out the leaf votes.
        for channel in self.leaf_channels.iter() {
            channel.send(()).await.unwrap();
        }

        // Send out the sibling votes.
        for channel in self.sibling_channels.iter() {
            channel.0.send(()).await.unwrap();
            channel.1.send(()).await.unwrap();
        }

        sleep(Duration::from_secs(10));

        //todo: Currently we're filling up a hashmap with the signatures. The next step is aggregating the signatures. On this lowest level we don't need the hax. It's cheap enough.

        //todo: Add an additional task that does the aggregation. (for now single threaded, but todo multi threaded).
        //todo: Aggregation task will now when done and can notify us here. So run starts by notifying aggregation task, then we send the aggregates up to the parents, and once they're out, we're notifying back here that it's all done.
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        for channel in self.leaf_channels.iter() {
            channel.send(()).await.unwrap();
        }
        for channel in self.sibling_channels.iter() {
            channel.0.send(()).await.unwrap();
            channel.1.send(()).await.unwrap();
        }
        for channel in self.parent_channels.iter() {
            channel.send(()).await.unwrap();
        }
    }
}

pub async fn connect_to_leaf_nodes(base_port : usize, range: usize, signature_sender: Sender<(usize, Signature)>) -> Vec<Sender<()>> {
    let mut channels = Vec::new();

    for i in 0..range {
        let port = base_port + i;
        let addr = format!("127.0.0.1:{}", port);
        println!("Connecting to {}", addr);

        let (tx, mut rx) = mpsc::channel::<()>(2);
        channels.push(tx);

        let mut stream = TcpStream::connect(&addr).await.unwrap();
        println!("Successfully connected to {}", addr);

        // Spawn a task to accept connections on this listener
        let tx_clone = signature_sender.clone();
        tokio::spawn(async move {

            // Wait to start reading messages.
            rx.recv().await;

            // We're just expecting a single message from each leaf node.
            let mut buffer = [0; 96];
            stream.read_exact(&mut buffer).await.unwrap();
            if let Ok(sig) = Signature::from_bytes(&buffer) {
                tx_clone.send((i.clone(), sig)).await.unwrap();
            } else {
                eprintln!("Invalid signature bytes");
            }
        });
    }
    channels
}

pub async fn setup_sibling_connection(base_port: usize, range: usize, sibling_signature_sender: Sender<(usize, Signature)>, mut sibling_signature_receiver2: Receiver<(usize, Signature)>, m: usize) -> Vec<(Sender<()>, Sender<()>)> {
    let mut channels = Vec::new();
    let mut channels2 = Vec::new();

    for i in 0..range {
        let port = base_port + i;
        let addr = format!("127.0.0.1:{}", port);
        println!("Connecting to {}", addr);
        let mut stream = TcpStream::connect(&addr).await.unwrap();

        let port_string = port.to_string();

        let (tx1, mut rx1) = mpsc::channel::<()>(2);
        let sender_copy = sibling_signature_sender.clone();

        let (mut reader, mut writer) = stream.into_split();
        let map = Arc::new(DashMap::new());

        let map2 = map.clone();
        task::spawn(async move {
            // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).
            // Awaiting sibling message.
            rx1.recv().await;
            loop {
                let mut mac_buffer = [0; 32];
                reader.read_exact(&mut mac_buffer).await.unwrap();

                let mut id_buffer = [0; size_of::<usize>()];
                reader.read_exact(&mut id_buffer).await.unwrap();
                let id = usize::from_be_bytes(id_buffer);

                let mut sig_buffer = [0; 96];
                reader.read_exact(&mut sig_buffer).await.unwrap();
                let sig = match Signature::from_bytes(&sig_buffer) {
                    Ok(sig) => {
                        sig
                    }
                    Err(err) => {
                        eprintln!("uhhhhhhhhhhhhherrrr {:?}", err);
                        return;
                    }
                };

                // This is the mac of the sender we're expecting here.
                let mut expected_mac = HmacSha256::new_from_slice(port_string.as_bytes());
                let mut unwrapped_mac = expected_mac.unwrap();
                unwrapped_mac.update(&sig.clone().to_bytes());

                if !unwrapped_mac.verify_slice(mac_buffer.as_slice()).is_ok() {
                    println!("Invalid Mac from {}", addr);
                    continue;
                }

                if map2.insert(id.clone(), sig.clone()).is_none() {
                    if !sender_copy.send((id, sig)).await.is_ok() {
                        // Close task after completion.
                        return;
                    }
                }
            }
        });

        let (tx2, mut rx2) = mpsc::channel::<(usize, Signature)>(m);
        channels2.push(tx2);

        task::spawn(async move {
            // Connect to sibling for sending.
            while let Some((id, sig)) = rx2.recv().await {
                if map.insert(id, sig.clone()).is_none() {
                    //todo also need to handle mac here.
                    let mut expected_mac = HmacSha256::new_from_slice(port_string.as_bytes());
                    let mut unwrapped_mac = expected_mac.unwrap();
                    unwrapped_mac.update(&sig.clone().to_bytes());
                    let vote = unwrapped_mac.finalize().into_bytes();

                    writer.write(&vote.to_vec()).await.unwrap();
                    writer.write(&sig.to_bytes()).await.unwrap();
                }
            }
        });
    }

    let mut receiver_copy = sibling_signature_receiver2;
    // Spawn a task to accept connections on this listener
    task::spawn(async move {
        // Connect to sibling for sending.
        while let Some((id, sig)) = receiver_copy.recv().await {
            for channel in channels2.iter() {
                channel.send((id, sig)).await.unwrap();
            }
        }
    });
    channels
}

pub async fn setup_parent_connections(base_port : usize, range: usize) -> Vec<Sender<()>> {
    let mut channels = Vec::new();

    for i in 0..range {
        let port = base_port + i;
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await.unwrap();
        println!("Listening on {}", addr);

        // Spawn a task to accept connections on this listener
        let (tx, mut rx) = mpsc::channel::<()>(2);
        channels.push(tx);

        task::spawn(async move {
            // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).
            match listener.accept().await {
                Ok((socket, addr)) => {
                    println!("New connection from {} on port {}", addr, port);

                    // Wait before closing connection.
                    rx.recv().await;

                    //todo send aggregates to leaders
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
    channels
}
