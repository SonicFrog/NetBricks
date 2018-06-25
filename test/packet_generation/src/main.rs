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
use e2d2::common::*;
use e2d2::headers::*;
use e2d2::interface::*;
use e2d2::native::zcsi::chain_pkts;
use e2d2::operators::*;
use e2d2::scheduler::*;
use e2d2::queues::*;
use e2d2::interface::Packet;

use std::env;
use std::fmt::Display;

use std::process;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use self::logmap::OptiMap;

const CONVERSION_FACTOR: f64 = 1000000000.;

pub struct PacketCreator {
    mac: MacHeader,
    ip: IpHeader,
    udp: UdpHeader,
    producer: MpscProducer,
}

impl PacketCreator {
    pub fn new(producer: MpscProducer) -> PacketCreator {
        let mut mac = MacHeader::new();

        mac.dst = MacAddress {
            addr: [ 0xb8, 0xca, 0x3a, 0x69, 0xcd, 0x78 ],
        };

        mac.src = MacAddress {
            addr: [ 0xb8, 0xca, 0x3a, 0x69, 0xcd, 0x79 ],
        };

        mac.set_etype(0x8000);

        let mut ip = IpHeader::new();
        ip.set_src(u32::from(Ipv4Addr::from_str("10.10.10.11").unwrap()));
        ip.set_dst(u32::from(Ipv4Addr::from_str("10.10.10.12").unwrap()));
        ip.set_ttl(128);
        ip.set_version(4);
        ip.set_ihl(5);
        ip.set_length(20);

        let mut udp = UdpHeader::new();


        udp.set_src_port(9000);
        udp.set_dst_port(9001);

        PacketCreator {
            mac: mac,
            ip: ip,
            udp: udp,
            producer: producer,
        }
    }

    fn init_packet(&self, pkt: Packet<NullHeader, EmptyMetadata>) -> Packet<UdpHeader, EmptyMetadata> {
        let hdr = new_packet().unwrap();
        let mut payload = pkt;

        let hdr = hdr.push_header(&self.mac)
            .unwrap()
            .push_header(&self.ip)
            .unwrap()
            .push_header(&self.udp)
            .unwrap();
        {
            let bytes = payload.get_mut_payload();

            bytes[0] = 0x01;
            bytes[1] = 0x02;
            bytes[2] = 0x03;
        }

        let mbuf_p = unsafe { payload.get_mbuf() };
        let mbuf_h = unsafe { hdr.get_mbuf() };

        unsafe {
            if chain_pkts(mbuf_h, mbuf_p) != 0 {
                panic!("failed to chain mbufs");
            }

            packet_from_mbuf(mbuf_h, 0)
        }
    }

    pub fn create_packet(&self) -> Packet<UdpHeader, EmptyMetadata> {
        self.init_packet(new_packet().unwrap())
    }
}

impl Executable for PacketCreator {
    fn execute(&mut self) {
        for _ in 0..16 {
            self.producer.enqueue_one(self.create_packet());
        }
    }

    fn dependencies(&mut self) -> Vec<usize> {
        vec![]
    }
}

fn test<T, S>(ports: Vec<T>, sched: &mut S)
    where
    T: PacketRx + PacketTx + Display + Clone + 'static,
    S: Scheduler + Sized,
{
    if ports.len() > 1 {
        panic!("more than one port");
    }

    println!("sending started");

    let (producer, consumer) = new_mpsc_queue_pair();
    let pipeline = consumer.send(ports[0].clone());
    let creator = PacketCreator::new(producer);
    sched.add_task(creator).unwrap();
    sched.add_task(pipeline).unwrap();
}

fn main() {
    let opts = basic_opts();

    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let configuration = read_matches(&matches, &opts);

    match initialize_system(&configuration) {
        Ok(mut context) => {
            context.start_schedulers();
            context.add_pipeline_to_run(Arc::new(move |p, s: &mut StandaloneScheduler| {
                test(p, s)
            }));
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
