use std::collections::{BTreeMap};
use std::sync::{Arc};
use std::time::Instant;
use async_channel::{Receiver, Sender};
use bit_vec::BitVec;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use fxhash::FxHashMap;
use hmac::digest::typenum::Bit;
use hmac::Mac;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast};
use crate::simulation::main::{HmacSha256, DST, RUN_POOL};

pub struct DepthBasedInternalAggregator {
    // Fanout.
    pub(crate) m: usize,
    // Proposal byte vector.
    pub proposal: Arc<Vec<byte>>,
    // Depth the node is in.
    pub depth: usize,
    // Total depth.
    pub total_depth: usize,
    // Smaller fanout at leader
    pub leader_divider: usize,
    // Channels to wake up children connection to start reading messages.
    pub child_channels: broadcast::Sender<()>,
    // Connection to send message to parents.
    pub parent_channels: broadcast::Sender<(BitVec, Signature, BitVec, Signature)>,
    // Public keys of all nodes in the system.
    pub public_keys: Arc<Vec<Arc<PublicKey>>>,
    // Channel to hand signatures that come from the children and process them.
    pub signature_receiver: Receiver<(usize, BitVec, Signature, PublicKey, BitVec, Signature, PublicKey)>
}

impl Default for DepthBasedInternalAggregator {
    fn default() -> Self {
        DepthBasedInternalAggregator {
            depth: 0,
            m: 0,
            total_depth: 0,
            leader_divider: 0,
            proposal: Arc::new(Vec::new()),
            child_channels: broadcast::Sender::new(2),
            parent_channels: broadcast::Sender::new(2),
            public_keys: Arc::new(Vec::new()),
            signature_receiver: async_channel::unbounded().1,
        }
    }
}

impl DepthBasedInternalAggregator {

    pub fn new(m: usize, depth: usize, total_depth: usize, proposal: &Vec<u8>, public_keys: Vec<Arc<PublicKey>>, leader_divider: usize) -> Self {
        DepthBasedInternalAggregator {
            depth,
            m,
            total_depth,
            leader_divider,
            proposal: Arc::new(proposal.clone()),
            public_keys: Arc::new(public_keys),
            ..Default::default()
        }
    }

    pub async fn open_connections(&mut self) {
        let base_port = 40_000 + 2000 * self.depth;

        let (signature_sender, signature_receiver) = async_channel::bounded(self.m);

        let expected_sigs = (self.m / 16).pow((self.total_depth - self.depth) as u32) * self.m;
        println!("Expected sigs: {} at {} at {}", expected_sigs, self.depth, base_port);
        connect_to_child_nodes(base_port, &self.proposal, &self.public_keys, &mut self.child_channels, signature_sender, expected_sigs).await;
        self.signature_receiver=signature_receiver;

        println!("Finished preparing internal aggregator connections");
    }

    // Prepare simulator. Open all necessary sockets and initiate signatures and public keys.
    pub async fn connect(&mut self) {
        if self.depth == 0 {
            // No parent connection.
        } else {
            let base_port = 40_000 + 2000 * (self.depth - 1);
            if self.depth == 1 {
                // Only the leader.
                setup_parent_connections(base_port, 1, &mut self.parent_channels).await;
            } else {
                // Next higher up group.
                setup_parent_connections(base_port, 128, &mut self.parent_channels).await;
            }
        }
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {

        // Activate the child connection to start receiving messages.
        self.child_channels.send(()).unwrap();

        println!("Finished preparing Validator sibling connections");

        let m_copy = self.m.clone() / self.leader_divider.clone();

        let mut biggest_result_map: BTreeMap<usize, (BitVec, Signature, PublicKey, u64)> = BTreeMap::new();

        let mut all_message_map = FxHashMap::default();
        let mut overlap_calc_map = FxHashMap::default();
        let mut overlap_bitvec_map = FxHashMap::default();

        let mut total_time = 0;
        let mut setup_time = 0;
        let mut total_count_time = 0;
        let mut runs = 0;
        while let Ok((idx, bit_vec, sig, pub_key, bit_vec2, sig2, pub2)) = self.signature_receiver.recv().await {
            runs+=1;
            let time_now = Instant::now();
            if let Some((local_bit_vec, local_sig, local_pub_key, local_bit_vec_ones)) = biggest_result_map.get(&idx) {
                let bit_vec_ones = bit_vec.count_ones();
                if bit_vec_ones > *local_bit_vec_ones {
                    // If bigger insert.
                    biggest_result_map.insert(idx, (bit_vec.clone(), sig, pub_key, bit_vec_ones));
                }
            } else {
                biggest_result_map.insert(idx, (bit_vec.clone(), sig, pub_key, bit_vec.count_ones()));

                let mut count_vec = Vec::new();
                for bit in bit_vec2.iter() {
                    if bit {
                        count_vec.push(1);
                    }
                    else {
                        count_vec.push(0);
                    }
                }
                overlap_calc_map.insert(idx, count_vec);
                overlap_bitvec_map.insert(idx, BitVec::from_elem(bit_vec2.len(), false));

                let mut overlap_vec = Vec::new();
                overlap_vec.push((bit_vec2, sig2, pub2));
                all_message_map.insert(idx, overlap_vec);

                total_time+=time_now.elapsed().as_millis();
                if runs >= m_copy {
                    break;
                }

                setup_time+=time_now.elapsed().as_millis();
                continue
            }

            //todo multithread
            //todo: store matrix as matrix in memory and then rea dcolumn and use bitwise magic.
            if let Some((mut le_vec)) = all_message_map.get_mut(&idx) {
                let count_vec = overlap_calc_map.get_mut(&idx).unwrap();
                let count_time = Instant::now();

                let mut index = 0;
                for subtype in bit_vec2.storage().iter() {
                    for i in (0..32).rev() {
                        let bit = (subtype >> i) & 1;
                        if bit != 0 {
                            count_vec[i + (index * 32)] += 1;
                        }
                    }
                    index += 1;
                }
                total_count_time+=count_time.elapsed().as_millis();
                // If bigger insert.
                le_vec.push((bit_vec2, sig2, pub2));
            }

            total_time+=time_now.elapsed().as_millis();
            if runs >= m_copy {
                break;
            }
        }

        let time_now_1 = Instant::now();
        for (local_idx, count_vec) in overlap_calc_map {
            // If more than 2 thirds
            if count_vec[local_idx] > ((m_copy as f64)/3.0*2.0) as usize {
                overlap_bitvec_map.get_mut(&local_idx).unwrap().set(local_idx, true);
            }
        }
        println!("took {}", time_now_1.elapsed().as_millis());

        let time_now = Instant::now();

        println!("Got all the sigs {} {} at depth {} total time {} {} {}", biggest_result_map.len(), overlap_bitvec_map.len(), self.depth, total_time, setup_time, total_count_time);
        let proposal_copy = self.proposal.clone();
        let biggest_future = RUN_POOL.spawn_blocking(move || {
            // do some expensive computation
            let mut pub_vec = Vec::new();
            let mut sig_vec = Vec::new();
            for (idx, (bit_vec, sig, pub_key, ones)) in biggest_result_map.iter() {
                sig_vec.push(sig);
                pub_vec.push(pub_key);
            }

            println!("Size 1: {} {}", pub_vec.len(), sig_vec.len());
            let agg_pub = AggregatePublicKey::aggregate(&pub_vec, false).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&sig_vec, false).unwrap().to_signature();

            // not necessary.
            // if !agg_sig.verify(false, &proposal_copy, DST, &[], &agg_pub, false).eq(&BLST_SUCCESS) {
            //    panic!("Failed to verify agg signature");
            //}
            return (agg_sig, agg_pub, biggest_result_map);
        });

        //todo we might find none, then take largest.
        let mut overlap_result_map = BTreeMap::new();
        for (idx, vec) in all_message_map {
            for (bit_vec, sig, pub_key) in vec {
                if bit_vec.clone().and(overlap_bitvec_map.get(&idx).unwrap()) {
                    overlap_result_map.insert(idx, (bit_vec, sig, pub_key));
                    // Already found one that matches.
                    break
                }
            }
        }

        let proposal_copy2 = self.proposal.clone();
        let overlap_future = RUN_POOL.spawn_blocking(move || {
            // do some expensive computation
            let mut pub_vec = Vec::new();
            let mut sig_vec = Vec::new();
            for (idx, (bit_vec, sig, pub_key)) in overlap_result_map.iter() {
                sig_vec.push(sig);
                pub_vec.push(pub_key);
            }

            println!("Size 2: {} {}", pub_vec.len(), sig_vec.len());
            let agg_pub = AggregatePublicKey::aggregate(&pub_vec, false).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&sig_vec, false).unwrap().to_signature();

            //not necessary.
            //if !agg_sig.verify(false, &proposal_copy2, DST, &[], &agg_pub, false).eq(&BLST_SUCCESS) {
            //    panic!("Failed to verify agg signature");
            //}
            return (agg_sig, agg_pub, overlap_result_map);
        });

        let ( biggest_agg_sig, biggest_pub, biggest_result_map) = biggest_future.await.unwrap();
        let ( overlap_agg_sig, overlap_pub, overlap_result_map) = overlap_future.await.unwrap();

        let mut biggest_bit_vec = BitVec::new();
        for (idx, (mut bit_vec, sig, pub_key, ones)) in biggest_result_map.into_iter() {
            biggest_bit_vec.append(&mut bit_vec);
        }

        let mut overlap_bit_vec = BitVec::new();
        for (idx, (mut bit_vec, sig, pub_key)) in overlap_result_map.into_iter() {
            overlap_bit_vec.append(&mut bit_vec);
        }

        println!("Finalized at: {}", time_now.elapsed().as_millis());

        // Leader has no further parent.
        if self.depth != 0 {
            self.parent_channels.send((biggest_bit_vec, biggest_agg_sig, overlap_bit_vec, overlap_agg_sig)).unwrap();
            self.parent_channels.closed().await;
        }
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        // Send out the leaf votes.
        let _ = self.child_channels.send(());
    }
}

// connect to m child nodes. So we assume they're al
pub async fn connect_to_child_nodes(base_port: usize, proposal: &Arc<Vec<byte>>, public_keys: &Arc<Vec<Arc<PublicKey>>>, sender: &broadcast::Sender<()>, signature_sender: Sender<(usize, BitVec, Signature, PublicKey, BitVec, Signature, PublicKey)>, expected_sigs: usize) {

    println!("Opening Port: {}", base_port);

    // Listen on base port for connection attempts.
    let port = base_port;
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await.unwrap();
    let mut local_sender = sender.clone();

    let sender_copy = signature_sender.clone();
    let public_keys_copy = public_keys.clone();
    let proposal_copy = proposal.clone();

    let expected_sigs_copy : usize = expected_sigs.clone();

    RUN_POOL.spawn(async move {
        loop {
            let mut rx = local_sender.subscribe();
            let port_string = port.to_string();
            let local_sender_copy = sender_copy.clone();
            let local_public_keys_copy = public_keys_copy.clone();
            let local_proposal_copy = proposal_copy.clone();
            let local_expected_sigs = expected_sigs_copy.clone();
            match listener.accept().await {
                Ok((mut socket, address)) => {

                    RUN_POOL.spawn(async move {

                        // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).

                        // Wait before starting operation
                        rx.recv().await.unwrap();

                        let mut group_id_buffer = [0; size_of::<usize>()];
                        socket.read_exact(&mut group_id_buffer).await.unwrap();
                        let group_id = usize::from_be_bytes(group_id_buffer);

                        let mut bit_vec_buffer = vec![0u8; local_expected_sigs / 8];
                        socket.read_exact(&mut bit_vec_buffer).await.unwrap();
                        let bit_vec = BitVec::from_bytes(&bit_vec_buffer);

                        let mut sig_buffer = [0; 96];
                        socket.read_exact(&mut sig_buffer).await.unwrap();
                        let sig = match Signature::from_bytes(&sig_buffer) {
                            Ok(sig) => {
                                sig
                            }
                            Err(err) => {
                                eprintln!("DBI: BLS load Error 1 {:?} {}", err, local_expected_sigs);
                                return;
                            }
                        };

                        let mut bit_vec_buffer2 = vec![0u8; local_expected_sigs / 8];
                        socket.read_exact(&mut bit_vec_buffer2).await.unwrap();
                        let bit_vec2 = BitVec::from_bytes(&bit_vec_buffer2);

                        let mut sig_buffer2 = [0; 96];
                        socket.read_exact(&mut sig_buffer2).await.unwrap();
                        let sig2 = match Signature::from_bytes(&sig_buffer2) {
                            Ok(sig2) => {
                                sig2
                            }
                            Err(err) => {
                                eprintln!("DBI: BLS load Error 2 {:?} {}", err, local_expected_sigs);
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
                            let start_index = group_id * local_expected_sigs;
                            for (local_index, available) in bit_vec.iter().enumerate() {
                                if available {
                                    let index = start_index + local_index;
                                    pubs.push(local_public_keys_copy.get(index).unwrap().as_ref());
                                }
                            }
                            let pub_key = AggregatePublicKey::aggregate(&pubs, false).unwrap().to_public_key();

                            let mut pubs2 = Vec::new();
                            for (local_index, available) in bit_vec2.iter().enumerate() {
                                if available {
                                    let index = start_index + local_index;
                                    pubs2.push(local_public_keys_copy.get(index).unwrap().as_ref());
                                }
                            }
                            let pub_key2 = AggregatePublicKey::aggregate(&pubs2, false).unwrap().to_public_key();

                            // This verify is only necessary in the worst case here. For a best/avg-case simulation we can drop this.
                            if sig.verify(false, &local_proposal_copy, DST, &[], &pub_key, false).eq(&BLST_SUCCESS) {
                                if sig2.verify(false, &local_proposal_copy, DST, &[], &pub_key2, false).eq(&BLST_SUCCESS) {
                                    local_sender_copy.send((group_id, bit_vec, sig, pub_key, bit_vec2, sig2, pub_key2)).await.unwrap();
                                } else {
                                    println!("DBI2: Invalid Sig from {}", address);
                                }
                            } else {
                                //todo not working?  
                                println!("DBI1: Invalid Sig from {}", address);
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


pub async fn setup_parent_connections(base_port : usize, range: usize, sender: &mut broadcast::Sender<(BitVec, Signature, BitVec, Signature)>) {
    for i in 0..range {
        let port = base_port + i;
        let addr = format!("127.0.0.1:{}", port);
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

                println!("send to: {} {} {}", i.clone(), port.clone(), bit_vec.len());

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
