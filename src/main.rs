mod calculation;
mod simulation;

#[tokio::main]
async fn main() {
    //calculation::tree_calc::run();
    simulation::main::main().await;
}