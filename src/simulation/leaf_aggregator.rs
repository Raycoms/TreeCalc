#![allow(non_snake_case)]

use std::sync::Arc;
use bit_vec::BitVec;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use dashmap::{DashMap};
use rand_core::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::simulation::main::{DST, RUN_POOL};
use tokio::net::{TcpStream};
use tokio::sync::{broadcast, mpsc};

pub struct LeafAggregator {
    // Fanout.
    pub(crate) m: usize,
    // Proposal byte vector.
    pub proposal: Arc<Vec<byte>>,
    pub public_key: PublicKey,
    pub private_key: Arc<SecretKey>,
    pub leaf_channels: broadcast::Sender<()>,
    pub parent_channels: broadcast::Sender<(BitVec, Signature)>,
    pub public_keys: Arc<Vec<Arc<PublicKey>>>,
    pub signature_map: Arc<DashMap<usize, Option<Signature>>>,
    pub ip: String,
}

impl Default for LeafAggregator {
    fn default() -> Self {
        LeafAggregator {
            m: 0,
            public_key: PublicKey::default(),
            private_key: Arc::new(SecretKey::default()),
            proposal: Arc::new(Vec::new()),
            leaf_channels: broadcast::Sender::new(2),
            parent_channels: broadcast::Sender::new(2),
            public_keys: Arc::new(Vec::new()),
            signature_map: Arc::new(DashMap::new()),
            ip: "127.0.0.1".to_string(),
        }
    }
}

impl LeafAggregator {

    pub fn new(m: usize, proposal: &Vec<u8>, public_keys: Vec<Arc<PublicKey>>, ip: &String, private_keys: &Vec<Arc<SecretKey>>) -> Self {
        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let private_key = private_keys.get(0).unwrap().clone();

        LeafAggregator {
            m,
            public_key: private_key.sk_to_pk(),
            private_key,
            proposal: Arc::new(proposal.clone()),
            public_keys: Arc::new(public_keys),
            ip: ip.clone(),
            ..Default::default()
        }
    }

    // Prepare simulator. Open all necessary sockets and initiate signatures and public keys.
    pub async fn connect(&mut self) {

        // We set up connections for: Leaf nodes, siblings & parent nodes.

        // Signature processing channel. todo move to constructor, those need to stay alive.
        let (mut signature_sender, mut signature_receiver) = async_channel::bounded(self.m);

        // Leaf nodes will send out messages to their parent
        connect_to_leaf_nodes( self.ip.clone(), 10_000, self.m, signature_sender, &mut self.leaf_channels).await;
        println!("Finished preparing Validator leaf connections");

        // So we could verify them all independently.
        for _ in 0..4 {
            let proposal = self.proposal.clone();

            let leaf_sig_map_copy = self.signature_map.clone();
            let local_public_keys = self.public_keys.clone();
            let signature_receiver_copy = signature_receiver.clone();
            RUN_POOL.spawn(async move {
                while let Ok((id, sig)) = signature_receiver_copy.recv().await {
                    if sig.verify(false, &proposal, DST, &[], local_public_keys.get(id).unwrap(), false).eq(&BLST_SUCCESS) {
                        leaf_sig_map_copy.insert(id.clone(), Some(sig.clone()));
                    } else {
                        println!("Got wrong signature from leaf. {}", id);
                    }
                }
            });
        }

        setup_parent_connections(self.ip.clone(), 30_000, 128, &mut self.parent_channels, &self.private_key).await;
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {

        // Send out the leaf votes.
        self.leaf_channels.send(()).unwrap();

        let (tx, rx) = async_channel::bounded(100);

        // How many sigs/pubs we want to aggregate in parallel.
        let PARALLEL_SLIZES = 50;

        let mut curr_index = 0;
        let mut vec = Vec::new();

        let sig_map_copy = self.signature_map.clone();
        let pub_map_copy = self.public_keys.clone();
        let m_copy = self.m.clone();
        let tx2 = tx.clone();
        RUN_POOL.spawn(async move {
            loop {
                // Drain dashmap here. Entry might've not yet synched. Or entry might be empty because of timeout.
                if let Some(the_sig) = sig_map_copy.get(&curr_index) {
                    if let Some(sig) = the_sig.as_ref() {
                        vec.push((curr_index.clone(), pub_map_copy.get(curr_index).unwrap().clone(), sig.clone()));
                    }
                    curr_index += 1;
                }

                if vec.len() >= PARALLEL_SLIZES {
                    let new_vec = vec.split_off(PARALLEL_SLIZES);
                    tx2.send(vec).await.unwrap();
                    vec = new_vec;
                }
                // After I got all stop querying them.
                if curr_index >= m_copy {
                    tx2.send(vec).await.unwrap();
                    drop(tx2);
                    break;
                }
            }
        });


        let (mut final_agg_sender, mut final_agg_receiver) = mpsc::channel(100);

        // Atm just 4, we want to make this more dynamic in the future.
        for _ in 0..4 {
            let mut rx2 = rx.clone();
            let mut final_agg_sender_copy = final_agg_sender.clone();
            let m = self.m;
            //let proposal  = self.proposal.clone();
            RUN_POOL.spawn(async move {
                'task: loop {
                    match rx2.recv().await {
                        Ok(sigs) => {
                            let mut pub_vec = Vec::with_capacity(sigs.len());
                            let mut sig_vec = Vec::with_capacity(sigs.len());
                            let mut pub_bit_vec = BitVec::from_elem(m, false);

                            for (idx, pub_key, sig) in sigs.iter() {
                                pub_vec.push(pub_key.as_ref());
                                sig_vec.push(sig);
                                pub_bit_vec.set(idx.clone(), true);
                            }

                            let agg_sig = AggregateSignature::aggregate(&sig_vec, false).unwrap();
                            let agg_pub = AggregatePublicKey::aggregate(&pub_vec, false).unwrap();

                            //agg_sig.to_signature().verify(false, &proposal, DST, &[], &agg_pub.to_public_key(), false);
                            final_agg_sender_copy.send((pub_bit_vec, agg_sig, agg_pub, pub_vec.len())).await.unwrap();
                        }
                        _ => break 'task
                    }
                }
            });
        }

        drop(tx);

        let (mut bit_vec, mut agg_sig, mut agg_pub, mut len) = final_agg_receiver.recv().await.unwrap();
        loop {
            let (local_bit_vec, local_agg_sig, local_agg_pub, local_len) = final_agg_receiver.recv().await.unwrap();
            agg_sig.add_aggregate(&local_agg_sig);
            agg_pub.add_aggregate(&local_agg_pub);
            len += local_len;
            bit_vec.or(&local_bit_vec);

            if len >= self.m {
                break;
            }
        }

        self.parent_channels.send((bit_vec, agg_sig.to_signature())).unwrap();
        self.parent_channels.closed().await;
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        // Send out the leaf votes.
        let _ = self.leaf_channels.send(());

        // Send out the sibling votes.
        //let _ = self.sibling_channels.send(());
    }
}

pub async fn connect_to_leaf_nodes(ip: String, base_port : usize, range: usize, signature_sender: async_channel::Sender<(usize, Signature)>, sender: &mut broadcast:: Sender<()>) {
    for i in 0..range {
        let port = base_port + i;
        let addr = format!("{}:{}", ip, port);

        let mut rx = sender.subscribe();

        let mut stream = TcpStream::connect(&addr).await.unwrap();

        // Spawn a task to accept connections on this listener
        let tx_clone = signature_sender.clone();
        RUN_POOL.spawn(async move {

            // Wait to start reading messages.
            rx.recv().await.unwrap();

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
}

pub async fn setup_parent_connections(ip: String, base_port : usize, range: usize, sender: &mut broadcast::Sender<(BitVec, Signature)>, private_key: &Arc<SecretKey>) {
    for i in 0..range {
        let port = base_port + i;
        let addr = format!("{}:{}", ip, port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();

        // Spawn a task to accept connections on this listener
        let mut rx = sender.subscribe();
        let private_key = private_key.clone();

        RUN_POOL.spawn(async move {

            // Connect to parent for sending.
            // Just send a single message and disconnect.
            if let Ok((bit_vec, agg_sig)) = rx.recv().await {

                let mut msg_bytes = agg_sig.to_bytes().to_vec();
                msg_bytes.append(&mut bit_vec.to_bytes().to_vec());

                let personal_sig = private_key.sign(&msg_bytes, DST, &[]);

                let index : usize = 0;
                stream.write(&index.to_be_bytes()).await.unwrap();
                stream.write(&bit_vec.to_bytes()).await.unwrap();
                stream.write(&agg_sig.to_bytes()).await.unwrap();
                stream.write(&personal_sig.to_bytes()).await.unwrap();
            }
        });
    }
}
