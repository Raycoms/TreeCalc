use std::sync::Arc;
use std::time::Instant;
use bit_vec::BitVec;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use dashmap::{DashMap};
use futures::channel;
use hmac::Mac;
use rand_core::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::simulation::main::{HmacSha256, DST};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
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
    pub parent_channels: Vec<Sender<(BitVec, Signature)>>,
    pub public_keys: Arc<Vec<Arc<PublicKey>>>,
    pub signature_map: Arc<DashMap<usize, Option<Signature>>>
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

    pub fn new(m: usize, proposal: &Vec<u8>, public_keys: Vec<Arc<PublicKey>>) -> Self {
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
        let (mut signature_sender, mut signature_receiver) = async_channel::bounded(self.m);

        // Leaf nodes will send out messages to their parent
        let (leaf_channels) = connect_to_leaf_nodes( 10_000, self.m, signature_sender).await;
        self.leaf_channels.extend(leaf_channels);
        println!("Finished preparing Validator leaf connections");


        let (mut sibling_signature_sender, mut sibling_signature_receiver) = async_channel::bounded(self.m * 128);

        let (mut sibling_signature_sender2, mut sibling_signature_receiver2) = async_channel::bounded(self.m * 128);

        let sibling_channels = setup_sibling_connection(20_000, 127, sibling_signature_sender, sibling_signature_receiver2, self.m).await;
        self.sibling_channels.extend(sibling_channels);
        println!("Finished preparing Validator sibling connections");

        // So we could verify them all independently.
        for i in 0..4 {
            let proposal = self.proposal.clone();

            let leaf_sig_map_copy = self.signature_map.clone();
            let local_public_keys = self.public_keys.clone();
            let sibling_signature_sender2_copy = sibling_signature_sender2.clone();
            let signature_receiver_copy = signature_receiver.clone();
            tokio::spawn(async move {
                while let Ok((id, sig)) = signature_receiver_copy.recv().await {
                    if sig.verify(false, &proposal, DST, &[], local_public_keys.get(id).unwrap(), false).eq(&BLST_SUCCESS) {
                        if leaf_sig_map_copy.insert(id.clone(), Some(sig.clone())).is_none() {
                            //println!("Main channel insert");
                            let _ = sibling_signature_sender2_copy.send((id, sig)).await;
                        }
                    } else {
                        println!("Got wrong signature from leaf.");
                    }
                }
            });
        }

        for i in 0..4 {
            let proposal2 = self.proposal.clone();
            let sibling_sig_map_copy = self.signature_map.clone();
            let local_public_keys2 = self.public_keys.clone();
            let sibling_signature_receiver_copy = sibling_signature_receiver.clone();
            tokio::spawn(async move {
                while let Ok((id, sig)) = sibling_signature_receiver_copy.recv().await {
                    if !sibling_sig_map_copy.contains_key(&id) {
                        if sig.verify(false, &proposal2, DST, &[], local_public_keys2.get(id).unwrap(), false).eq(&BLST_SUCCESS) {
                            if sibling_sig_map_copy.insert(id.clone(), Some(sig.clone())).is_none() {
                                //println!("Side channel insert");
                            }
                        } else {
                            println!("Got wrong signature from sibling.");
                        }
                    }
                }
            });
        }

        let parent_channels = setup_parent_connections(30_000, 128).await;
        self.parent_channels.extend(parent_channels);
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

        let (tx, rx) = async_channel::bounded(100);

        // How many sigs/pubs we want to aggregate in parallel.
        let PARALLEL_SLIZES = 50;

        let mut curr_index = 0;
        let mut vec = Vec::new();

        let sig_map_copy = self.signature_map.clone();
        let pub_map_copy = self.public_keys.clone();
        let m_copy = self.m.clone();
        let tx2 = tx.clone();
        task::spawn(async move {
            let time_now = Instant::now();

            loop {
                // Drain dashmap here. Entry might've not yet synched. Or entry might be empty because of timeout.
                if let Some(the_sig) = sig_map_copy.get(&curr_index) {
                    if let Some(sig) = the_sig.as_ref() {
                        vec.push((pub_map_copy.get(curr_index).unwrap().clone(), sig.clone()))
                    }
                    curr_index += 1;
                }

                if vec.len() >= PARALLEL_SLIZES {
                    println!("Sent first set! {} {}", vec.len(), time_now.elapsed().as_millis());

                    let new_vec = vec.split_off(PARALLEL_SLIZES);
                    tx2.send(vec).await.unwrap();
                    vec = new_vec;
                }
                // After I got all stop querying them.
                if curr_index >= m_copy {
                    println!("Sent last set! {} {}", vec.len(), time_now.elapsed().as_millis());

                    tx2.send(vec).await.unwrap();
                    drop(tx2);
                    break;
                }
            }
        });


        let (mut final_agg_sender, mut final_agg_receiver) = mpsc::channel(100);

        // Atm just 4, we want to make this more dynamic in the future.
        for i in 0..4 {
            let mut rx2 = rx.clone();
            let mut final_agg_sender_copy = final_agg_sender.clone();
            //let proposal  = self.proposal.clone();
            tokio::spawn(async move {
                'task: loop {
                    match rx2.recv().await {
                        Ok(sigs) => {
                            let mut pub_vec = Vec::with_capacity(sigs.len());
                            let mut sig_vec = Vec::with_capacity(sigs.len());
                            for (id, sig) in sigs.iter() {
                                pub_vec.push(id.as_ref());
                                sig_vec.push(sig);
                            }

                            let agg_sig = AggregateSignature::aggregate(&sig_vec, false).unwrap();
                            let agg_pub = AggregatePublicKey::aggregate(&pub_vec, false).unwrap();

                            //agg_sig.to_signature().verify(false, &proposal, DST, &[], &agg_pub.to_public_key(), false);
                            final_agg_sender_copy.send((agg_sig, agg_pub, pub_vec.len())).await.unwrap();
                            println!("Sent an agg!");
                        }
                        _ => break 'task
                    }
                }
            });
        }

        drop(tx);

        let (mut agg_sig, mut agg_pub, mut len) = final_agg_receiver.recv().await.unwrap();
        loop {
            let (local_agg_sig, local_agg_pub, local_len) = final_agg_receiver.recv().await.unwrap();
            agg_sig.add_aggregate(&local_agg_sig);
            agg_pub.add_aggregate(&local_agg_pub);
            len += local_len;
            println!("got {}", len);

            if len >= self.m {
                break;
            }
        }

        //todo send aggregate to parents and notify run thread once it's done.
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
    }
}

pub async fn connect_to_leaf_nodes(base_port : usize, range: usize, signature_sender: async_channel::Sender<(usize, Signature)>) -> Vec<Sender<()>> {
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

pub async fn setup_sibling_connection(base_port: usize, range: usize, sibling_signature_sender: async_channel::Sender<(usize, Signature)>, mut sibling_signature_receiver2: async_channel::Receiver<(usize, Signature)>, m: usize) -> Vec<(Sender<()>, Sender<()>)> {
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
            let mut received_messages = 0;
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

                received_messages+=1;
                if received_messages >= m {
                    return;
                }
            }
        });

        let (tx2, mut rx2) = mpsc::channel::<(usize, Signature)>(m);
        channels2.push(tx2);

        task::spawn(async move {
            // Connect to sibling for sending.
            while let Some((id, sig)) = rx2.recv().await {
                if map.insert(id, sig.clone()).is_none() {
                    let mut expected_mac = HmacSha256::new_from_slice("128".as_bytes());
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
        while let Ok((id, sig)) = receiver_copy.recv().await {
            for channel in channels2.iter() {
                channel.send((id, sig)).await.unwrap();
            }
        }
    });
    channels
}

pub async fn setup_parent_connections(base_port : usize, range: usize) -> Vec<Sender<(BitVec, Signature)>> {
    let mut channels = Vec::new();

    for i in 0..range {
        let port = base_port + i;
        let addr = format!("127.0.0.1:{}", port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();
        println!("Listening on {}", addr);

        // Spawn a task to accept connections on this listener
        let (tx, mut rx) = mpsc::channel::<(BitVec, Signature)>(2);
        channels.push(tx);

        task::spawn(async move {
            // Connect to sibling for sending.
            while let Some((bitvec, sig)) = rx.recv().await {
                stream.write(&bitvec.to_bytes()).await.unwrap();
                stream.write(&sig.to_bytes()).await.unwrap();
            }
        });
    }
    channels
}
