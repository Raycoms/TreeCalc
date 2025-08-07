use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc};
use async_channel::{Receiver, Sender};
use bit_vec::BitVec;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use hmac::digest::typenum::Bit;
use hmac::Mac;
use rand::{thread_rng, Rng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast};
use crate::simulation::main::{HmacSha256, DST, RUN_POOL};

pub struct FirstInternalAggregator {
    // Fanout.
    pub(crate) m: usize,
    // Depth they are in.
    pub depth: usize,
    // Proposal byte vector.
    pub proposal: Arc<Vec<byte>>,
    // Channels to wake up children connection to start reading messages.
    pub child_channels: broadcast::Sender<()>,
    // Connection to send message to parents.
    pub parent_channels: broadcast::Sender<(BitVec, Signature, BitVec, Signature)>,
    // Public keys of all nodes in the system.
    pub public_keys: Arc<Vec<Arc<PublicKey>>>,
    // Channel to hand signatures that come from the children and process them.
    pub signature_receiver: Receiver<(usize,BitVec, Signature, PublicKey)>,
    pub ip : String
}

impl Default for FirstInternalAggregator {
    fn default() -> Self {
        FirstInternalAggregator {
            m: 0,
            depth: 2,
            proposal: Arc::new(Vec::new()),
            child_channels: broadcast::Sender::new(2),
            parent_channels: broadcast::Sender::new(2),
            public_keys: Arc::new(Vec::new()),
            signature_receiver: async_channel::unbounded().1,
            ip: "127.0.0.1".to_string()
        }
    }
}

impl FirstInternalAggregator {

    pub fn new(m: usize, depth: usize, proposal: &Vec<u8>, public_keys: Vec<Arc<PublicKey>>, ip: &String) -> Self {
        FirstInternalAggregator {
            m,
            depth,
            proposal: Arc::new(proposal.clone()),
            public_keys: Arc::new(public_keys),
            ip: ip.clone(),
            ..Default::default()
        }
    }

    pub async fn open_connections(&mut self) {

        let (signature_sender, signature_receiver) = async_channel::bounded(self.m);
        connect_to_child_nodes(self.ip.clone(), self.m, 30_000, &self.proposal, &self.public_keys, &mut self.child_channels, signature_sender).await;
        self.signature_receiver=signature_receiver;

        println!("Finished preparing internal aggregator connections");
    }

    // Prepare simulator. Open all necessary sockets and initiate signatures and public keys.
    pub async fn connect(&mut self) {
        let base_port = 40_000 + (self.depth - 1) * 2000;
        // Currently just leader, in the future this has to be a setting.
        setup_parent_connections(self.ip.clone(), base_port, 128, &mut self.parent_channels).await;
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {

        // Activate the child connection to start receiving messages.
        self.child_channels.send(()).unwrap();

        println!("Finished preparing Validator sibling connections");

        let m_copy = self.m.clone();

        let mut biggest_result_map: BTreeMap<usize, (BitVec, Signature, PublicKey)> = BTreeMap::new();
        let mut random_map: HashMap<usize, Vec<(BitVec, Signature, PublicKey)>> = HashMap::default();

        let mut runs = 0;
        while let Ok((idx, bit_vec, sig, pub_key)) = self.signature_receiver.recv().await {
            runs+=1;

            if let Some((local_bit_vec, local_sig, local_pub_key)) = biggest_result_map.get(&idx) {
                if bit_vec.count_ones() > local_bit_vec.count_ones() {
                    // If bigger insert.
                    random_map.get_mut(&idx).unwrap().push((local_bit_vec.clone(), local_sig.clone(), local_pub_key.clone()));
                    biggest_result_map.insert(idx, (bit_vec.clone(), sig, pub_key));
                }
                else {
                    random_map.get_mut(&idx).unwrap().push((bit_vec.clone(), sig, pub_key));
                }
            } else {
                biggest_result_map.insert(idx, (bit_vec.clone(), sig, pub_key));

                let mut vec = Vec::new();
                vec.push((bit_vec.clone(), sig, pub_key));
                random_map.insert(idx, vec);

                continue
            }

            if runs >= m_copy {
                break;
            }
        }

        println!("Got all the sigs {} {}", biggest_result_map.len(), random_map.len());

        let proposal_copy = self.proposal.clone();
        let biggest_future = RUN_POOL.spawn_blocking(move || {
            // do some expensive computation
            let mut pub_vec = Vec::new();
            let mut sig_vec = Vec::new();
            let mut result_bit_vec = BitVec::new();
            for (idx, (bit_vec, sig, pub_key)) in biggest_result_map.iter() {
                result_bit_vec.extend(bit_vec);
                sig_vec.push(sig);
                pub_vec.push(pub_key);
            }

            // let agg_pub = AggregatePublicKey::aggregate(&pub_vec, false).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&sig_vec, false).unwrap().to_signature();

            //disable, not necessary.
            //if !agg_sig.verify(false, &proposal_copy, DST, &[], &agg_pub, false).eq(&BLST_SUCCESS) {
            //    panic!("Failed to verify agg signature");
            //}
            return (result_bit_vec, agg_sig);
        });

        let proposal_copy2 = self.proposal.clone();
        let random_future = RUN_POOL.spawn_blocking(move || {
            // do some expensive computation
            let mut pub_vec = Vec::new();
            let mut sig_vec = Vec::new();
            let mut result_bit_vec = BitVec::new();
            for (idx, vec) in random_map.iter() {
                let (bit_vec, sig, pub_key) = vec.get(thread_rng().gen_range(0..(vec.len()-1))).unwrap();
                result_bit_vec.extend(bit_vec);
                sig_vec.push(sig);
                pub_vec.push(pub_key);
            }

            // let agg_pub = AggregatePublicKey::aggregate(&pub_vec, false).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&sig_vec, false).unwrap().to_signature();

            //disable, not necessary.
            //if !agg_sig.verify(false, &proposal_copy2, DST, &[], &agg_pub, false).eq(&BLST_SUCCESS) {
            //    panic!("Failed to verify agg signature");
            //}
            return (result_bit_vec, agg_sig);
        });

        let (biggest_bit_vec, biggest_agg_sig) = biggest_future.await.unwrap();
        let (random_bit_vec, random_agg_sig) = random_future.await.unwrap();

        self.parent_channels.send((biggest_bit_vec, biggest_agg_sig, random_bit_vec, random_agg_sig)).unwrap();
        self.parent_channels.closed().await;
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        // Send out the leaf votes.
        self.child_channels.send(()).unwrap();
    }
}

// connect to m child nodes. So we assume they're al
pub async fn connect_to_child_nodes(ip: String, m: usize, base_port: usize, proposal: &Arc<Vec<byte>>, public_keys: &Arc<Vec<Arc<PublicKey>>>, sender: &broadcast::Sender<()>, signature_sender: Sender<(usize, BitVec, Signature, PublicKey)>) {

    // Listen on base port for connection attempts.
    let port = base_port;
    let addr = format!("{}:{}", ip, port);
    let listener = TcpListener::bind(&addr).await.unwrap();

    println!("Listening on {}", addr);
    let mut local_sender = sender.clone();

    let sender_copy = signature_sender.clone();
    let public_keys_copy = public_keys.clone();
    let proposal_copy = proposal.clone();
    let m_copy = m.clone();
    RUN_POOL.spawn(async move {
        for _ in 0..m_copy {
            let mut rx = local_sender.subscribe();
            let port_string = port.to_string();
            let local_sender_copy = sender_copy.clone();
            let local_public_keys_copy = public_keys_copy.clone();
            let local_proposal_copy = proposal_copy.clone();
            let local_m_copy = m_copy.clone();
            match listener.accept().await {
                Ok((mut socket, address)) => {

                    RUN_POOL.spawn(async move {
                        // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).

                        // Wait before starting operation
                        rx.recv().await.unwrap();

                        let mut group_id_buffer = [0; size_of::<usize>()];
                        socket.read_exact(&mut group_id_buffer).await.unwrap();
                        let group_id = usize::from_be_bytes(group_id_buffer);

                        let mut bit_vec_buffer = vec![0u8; local_m_copy / 8];
                        socket.read_exact(&mut bit_vec_buffer).await.unwrap();
                        let bit_vec = BitVec::from_bytes(&bit_vec_buffer);

                        let mut sig_buffer = [0; 96];
                        socket.read_exact(&mut sig_buffer).await.unwrap();
                        let sig = match Signature::from_bytes(&sig_buffer) {
                            Ok(sig) => {
                                sig
                            }
                            Err(err) => {
                                eprintln!("FI: BLS load Error 1 {:?}", err);
                                return;
                            }
                        };

                        let mut mac_buffer = [0; 32];
                        socket.read_exact(&mut mac_buffer).await.unwrap();

                        // This is the mac of the sender we're expecting here.
                        let expected_mac = HmacSha256::new_from_slice(port_string.as_bytes());
                        let mut unwrapped_mac = expected_mac.unwrap();
                        unwrapped_mac.update(&sig.clone().to_bytes());

                        if !unwrapped_mac.verify_slice(mac_buffer.as_slice()).is_ok() {
                            println!("Invalid Mac from {}", address);
                        } else {


                            let mut pubs = Vec::new();
                            let start_index = group_id * local_m_copy;
                            for (local_index, available) in bit_vec.iter().enumerate() {
                                if available {
                                    let index = start_index + local_index;
                                    pubs.push(local_public_keys_copy.get(index).unwrap().as_ref());
                                }
                            }
                            let pub_key = AggregatePublicKey::aggregate(&pubs, false).unwrap().to_public_key();

                            // This verify is only necessary in the worst case here. For a best/avg-case simulation we can drop this.
                            if sig.verify(false, &local_proposal_copy, DST, &[], &pub_key, false).eq(&BLST_SUCCESS) {
                                local_sender_copy.send((group_id, bit_vec, sig, pub_key)).await.unwrap();
                            } else {
                                println!("FI: Invalid Sig from {} {}", group_id, address);
                            }
                        }

                        // Wait before closing connection.
                        rx.recv().await.unwrap();
                    });
                }
                e => {
                    println!("Connection from {:?} not accepted", e);
                }
            }
        }
    });
}


pub async fn setup_parent_connections(ip: String, base_port : usize, range: usize, sender: &mut broadcast::Sender<(BitVec, Signature, BitVec, Signature)>) {
    for i in 0..range {
        let port = base_port + i;
        let addr = format!("{}:{}", ip, port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();
        let port_string = port.to_string();

        // Spawn a task to accept connections on this listener
        let mut rx = sender.subscribe();

        RUN_POOL.spawn(async move {

            let expected_mac = HmacSha256::new_from_slice(port_string.as_bytes());
            let mut unwrapped_mac = expected_mac.unwrap();

            // Connect to parent for sending.
            // Just send a single message and disconnect.
            if let Ok((bit_vec, sig, bit_vec2, sig2)) = rx.recv().await {
                unwrapped_mac.update(&sig.clone().to_bytes());

                let index : usize = 0;
                stream.write(&index.to_be_bytes()).await.unwrap();

                stream.write(&bit_vec.to_bytes()).await.unwrap();
                stream.write(&sig.to_bytes()).await.unwrap();

                stream.write(&bit_vec2.to_bytes()).await.unwrap();
                stream.write(&sig2.to_bytes()).await.unwrap();

                stream.write(&unwrapped_mac.finalize().into_bytes()).await.unwrap();
            }
        });
    }
}
