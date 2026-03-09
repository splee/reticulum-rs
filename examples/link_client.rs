use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let mut transport = Transport::new(TransportConfig::default());

    log::info!("start tcp app");

    {
        transport
            .spawn_interface(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn, "TCPInterface[127.0.0.1:4242]")
            .await;
    }

    let identity = PrivateIdentity::new_from_name("link-example");

    let in_destination = transport
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "linkexample").unwrap(),
        )
        .await;

    transport.send_announce(&in_destination, None).await;

    tokio::spawn(async move {
        let recv = transport.recv_announces();
        let mut recv = recv.await;
        loop {
            if let Ok(announce) = recv.recv().await {
                log::debug!(
                    "destination announce {}",
                    announce.destination.address_hash
                );

                let _link = transport.link(announce.destination).await;
            }
        }
    });


    let _ = tokio::signal::ctrl_c().await;
}
