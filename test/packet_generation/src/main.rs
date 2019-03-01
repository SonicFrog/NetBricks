#![feature(integer_atomics)]
#![feature(try_from)]
#![feature(box_syntax)]
#![feature(asm)]
extern crate e2d2;
extern crate fnv;
extern crate getopts;
extern crate logmap;
extern crate rand;
extern crate time;

use e2d2::config::{basic_opts, read_matches};
use e2d2::scheduler::*;

use std::env;
use std::net::Ipv4Addr;
use std::process;
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::thread;
use std::time::Duration;

mod nf;
mod r2p2;
mod redis;

const CONVERSION_FACTOR: f64 = 1000000000.;

use self::redis::RedisServer;

struct Container<T> {
    tx: Sender<T>,
}

unsafe impl<T> Send for Container<T> {}
unsafe impl<T> Sync for Container<T> {}

fn main() {
    let opts = basic_opts();

    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let configuration = read_matches(&matches, &opts);
    let (tx, rx) = channel();
    let sender = Container { tx };

    match initialize_system(&configuration) {
        Ok(mut context) => {
            context.start_schedulers();
            context.add_pipeline_to_run(
                Arc::new(move |p, s: &mut StandaloneScheduler| {
                    let addr = Ipv4Addr::new(10, 90, 44, 214);
                    let server = RedisServer::new(p, s, addr, 9000);

                    sender.tx.send(server).unwrap();
                }),
            );

            let _server = rx.recv().unwrap();

            context.execute();

            let mut pkts_so_far = (0, 0);
            let mut last_printed = 0.;
            const MAX_PRINT_INTERVAL: f64 = 30.;
            const PRINT_DELAY: f64 = 15.;
            let sleep_delay = (PRINT_DELAY / 2.) as u64;
            let mut start = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
            let sleep_time = Duration::from_millis(sleep_delay);
            println!("0 OVERALL RX 0.00 TX 0.00 CYCLE_PER_DELAY 0 0 0");
            loop {
                thread::sleep(sleep_time); // Sleep for a bit
                let now = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
                if now - start > PRINT_DELAY {
                    let mut rx = 0;
                    let mut tx = 0;
                    for port in context.ports.values() {
                        for q in 0..port.rxqs() {
                            let (rp, tp) = port.stats(q);
                            rx += rp;
                            tx += tp;
                        }
                    }
                    let pkts = (rx, tx);
                    let rx_pkts = pkts.0 - pkts_so_far.0;
                    if rx_pkts > 0 || now - last_printed > MAX_PRINT_INTERVAL {
                        println!(
                            "{:.2} OVERALL RX {:.2} TX {:.2}",
                            now - start,
                            rx_pkts as f64 / (now - start),
                            (pkts.1 - pkts_so_far.1) as f64 / (now - start)
                        );
                        last_printed = now;
                        start = now;
                        pkts_so_far = pkts;
                    }
                }
            }
        }
        Err(ref e) => {
            println!("Error: {}", e);
            if let Some(backtrace) = e.backtrace() {
                println!("Backtrace: {:?}", backtrace);
            }
            process::exit(1);
        }
    }
}
