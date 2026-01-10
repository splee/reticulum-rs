//! Test PLAIN destination address hash computation
//!
//! This binary computes PLAIN destination hashes for comparison with Python.

use std::env;

use reticulum::destination::plain::PlainDestination;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <app_name> <aspects>", args[0]);
        std::process::exit(1);
    }

    let app_name = &args[1];
    let aspects = &args[2];

    let dest = PlainDestination::new(app_name, aspects);
    let hash_hex = hex::encode(dest.address_hash().as_slice());

    println!("PLAIN_HASH={}", hash_hex);
    println!("STATUS=OK");
}
