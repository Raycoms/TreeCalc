mod calculation;
mod simulation;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    //calculation::tree_calc::run();
    simulation::main::main().await;
}