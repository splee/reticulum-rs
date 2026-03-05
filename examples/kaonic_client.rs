use std::env;
use std::sync::Arc;
use std::time::Duration;

use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::kaonic::kaonic_grpc::KaonicGrpc;
use reticulum::iface::kaonic::{RadioConfig, RadioModule};
use reticulum::transport::{Transport, TransportConfig};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <grpc-addr>", args[0]);
        return;
    }

    let grpc_addr = &args[1];

    let transport = Arc::new(Mutex::new(Transport::new(TransportConfig::default())));

    log::info!("start kaonic client");

    let _ = transport.lock().await.spawn_interface(
        KaonicGrpc::new(
            format!("http://{}", grpc_addr),
            RadioConfig::new_for_module(RadioModule::RadioA),
            None,
        ),
        KaonicGrpc::spawn,
    ).await;

    let identity = PrivateIdentity::new_from_name("kaonic-example");

    let in_destination = transport
        .lock()
        .await
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "linkexample").unwrap(),
        )
        .await;

    // Announce task
    {
        let transport = transport.clone();
        tokio::spawn(async move {
            loop {
                log::trace!("announce");

                transport
                    .lock()
                    .await
                    .send_announce(&in_destination, None)
                    .await;

                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
