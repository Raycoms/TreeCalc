use std::sync::Arc;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use hmac::Mac;
use log::info;
use rand_core::RngCore;
use tokio::io::{AsyncWriteExt};
use crate::simulation::main::{ DST};
use tokio::net::{TcpListener};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Sender;
use tokio::task;

pub struct LeafNode {
    // Fanout.
    pub(crate) m: usize,
    // Proposal byte vector.
    pub proposal: Arc<Vec<byte>>,
    pub public_keys: Arc<Vec<Arc<PublicKey>>>,
    pub my_sig: Signature,
    pub agg_sig: Signature,
    pub parent_channels: broadcast::Sender<(Signature)>,
}

impl LeafNode {

    pub fn new(m: usize, proposal: &Vec<u8>, public_keys: Vec<Arc<PublicKey>>, my_sig: Signature, agg_sig: Signature) -> Self {
        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        LeafNode {
            m,
            proposal: Arc::new(proposal.clone()),
            public_keys: Arc::new(public_keys),
            my_sig,
            agg_sig,
            parent_channels: Sender::new(2)
        }
    }

    // Prepare simulator. Open all necessary sockets and initiate signatures and public keys.
    pub async fn connect(&mut self) {

        // We set up connections for: parent nodes.
        setup_parent_connections(10_000, self.m, &mut self.parent_channels).await;
        println!("Finished preparing leaf connections");
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {
        println!("Starting up Leaf node");

        let mut handles = Vec::new();
        for i in 0..4 {
            let share = self.public_keys.len()/4;
            let pubs_copy = self.public_keys.clone();
            let j = i.clone()*share;
            handles.push(tokio::spawn(async move {
                let mut pub_vec = Vec::new();
                for index in j..(j+share){
                    pub_vec.push(pubs_copy.get(index).unwrap().as_ref());
                }

                AggregatePublicKey::aggregate(&pub_vec, false).unwrap().to_public_key()
            }));
        }

        let mut final_pub_vec = Vec::new();
        for handle in handles {
            final_pub_vec.push(handle.await.unwrap());
        }

        let final_pub_vec = final_pub_vec.iter().collect::<Vec<&PublicKey>>();

        let agg_pub = AggregatePublicKey::aggregate(&final_pub_vec, false).unwrap().to_public_key();


        // This is the same proposal we're signing, but that's okay. It's just for complexity sake.
        if !self.agg_sig.verify(false, &self.proposal, DST, &[], &agg_pub, false).eq(&BLST_SUCCESS) {
           panic!("Failed to verify agg signature");
        }
        self.parent_channels.send(self.my_sig.clone()).unwrap();
        println!("Awaiting sending proposal");
        self.parent_channels.closed().await;
    }
}

pub async fn setup_parent_connections(base_port : usize, range: usize, sender: &mut Sender<(Signature)>) {
    for i in 0..(range -1) {
        let port = base_port + 1000 + i;
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await.unwrap();

        // Spawn a task to accept connections on this listener
        let mut rx2 = sender.subscribe();

        task::spawn(async move {
            match listener.accept().await {
                Ok((mut socket, addr)) => {
                    // Spawn a new task for each connection
                    if let Ok((sig)) = rx2.recv().await {
                        socket.write(&sig.to_bytes()).await.unwrap();
                    }
                    drop(rx2);
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }

    let addr = format!("127.0.0.1:{}", base_port);

    let listener = TcpListener::bind(&addr).await.unwrap();
    let mut rx = sender.subscribe();
    task::spawn(async move {
        // Spawn a task to accept connections on this listener

        match listener.accept().await {
            Ok((mut socket, addr)) => {
                // Spawn a new task for each connection
                if let Ok((sig)) = rx.recv().await {
                    socket.write(&sig.to_bytes()).await.unwrap();
                }
                drop(rx);
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    });
}
