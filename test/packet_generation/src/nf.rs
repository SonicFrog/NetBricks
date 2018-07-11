extern crate logmap;

use e2d2::common::EmptyMetadata;
use e2d2::headers::*;
use e2d2::interface::*;
use e2d2::native::zcsi::{send_pkts, ipv4_cksum, MBuf};
use e2d2::operators::{Batch, ReceiveBatch};
use e2d2::queues::{new_mpsc_queue_pair, MpscProducer};
use e2d2::scheduler::{Executable, Scheduler};

use std::boxed::Box;
use std::fmt::Display;
use std::mem;
use std::net::Ipv4Addr;
use std::slice;
use std::str::from_utf8;
use std::result::Result;
use std::sync::Arc;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use super::r2p2::R2P2Header;
use self::logmap::LoanMap;

pub type Socket = u64;

/// A NetBricks UDP stack
pub struct UdpStack<T>
where
    T: PacketRx + PacketTx + Clone + 'static,
{
    // the last fd for the last opened socket
    fd: AtomicU64,
    // all opened sockets are contained in this map
    sockets: LoanMap<Socket, Arc<UdpSocket>>,
    // the PMD ports that this stack runs on
    ports: Vec<T>,

    // network packet sender
    pkt_out: Sender<Packet<R2P2Header, EmptyMetadata>>,
}

unsafe impl<T> Send for UdpStack<T>
where T: PacketRx + PacketTx + Clone + 'static {}

unsafe impl<T> Sync for UdpStack<T>
where T: PacketRx + PacketTx + Clone + 'static {}

trait SocketID {
    type Addr: PartialEq;
    type Port: PartialEq;

    fn addr(&self) -> Self::Addr;
    fn port(&self) -> Self::Port;
}

impl<T> UdpStack<T>
where
    T: PacketRx + PacketTx + Clone + 'static,
{
    fn setup_udp_recv<S>(ports: Vec<T>, sched: &mut S) -> Arc<UdpStack<T>>
    where S: Scheduler + Sized,
    {
        println!("Setting up UDP recv pipelines...");

        let stack = Arc::new(UdpStack::new(ports.clone(), sched));
        let ret = Arc::clone(&stack);

        // Receiving setup
        let recv_pipeline = ports
            .iter()
            .map(|port| {
                let stack = Arc::clone(&stack);

                ReceiveBatch::new(port.clone())
                    .parse::<MacHeader>()
                    .parse::<IpHeader>()
                    .metadata(box move |pkt|{
                        // keep the source ip around for later replies
                        pkt.get_header().src()
                    })
                    .parse::<UdpHeader>()
                    .map(box move |pkt| {
                        let addr = Ipv4Addr::from(*pkt.read_metadata());
                        let port = pkt.get_header().dst_port() as u64;

                        stack.sockets.get(&port).map(|sock| {
                            let mut tmp = CrossPacket::from(pkt);
                            let len = IpHeader::size() + MacHeader::size() +
                                UdpHeader::size();
                            let src_port = pkt.get_header().src_port() as u16;

                            tmp.remove_data_head(len);

                            sock.deliver(tmp, addr, src_port);
                        });
                    })
                    .compose()
            });

        for pipeline in recv_pipeline  {
            sched.add_task(pipeline)
                .expect("failed to setup recv pipeline");
        }

        println!("UDP receiver setup done!");

        ret
    }

    /// Runs a new stack on the given scheduler utilizing the given `PortQueue`s
    /// The user provides a setup function that is executed on the resulting
    /// UdpStack after creation
    pub fn run_stack_on<F, S, V>(ports: Vec<T>,
                                 sched: &mut S, setup: F) -> (Arc<UdpStack<T>>, V)
    where F: (FnOnce(&Arc<UdpStack<T>>) -> V) + 'static,
          S: Scheduler + Sized,
          V: Sized,
    {
        let stack = UdpStack::setup_udp_recv(ports, sched);
        let result = setup(&stack);

        (stack, result)
    }

    pub fn socket_for(&self, sock: u64) -> Arc<UdpSocket> {
        self.sockets.get(&sock).unwrap().clone()
    }

    /// Creates a new UDPStack on the given scheduler using the given `PortQueue`s
    pub fn new<S>(ports: Vec<T>, sched: &mut S) -> UdpStack<T>
    where S: Scheduler + Sized,
    {
        if ports.len() > 1{
            println!("using more than one TX ring is currently unsupported");
        }

        let (send, recv) = channel();

        let stack = UdpStack {
            fd: AtomicU64::new(0),
            ports: ports.clone(),
            sockets: LoanMap::with_capacity(65536, 1),
            pkt_out: send,
        };

        sched.add_task(UdpSender::new(recv, ports[0].clone()))
            .expect("failed to setup udp sending");

        stack
    }

    /// Binds a new socket on this UDPStack
    pub fn bind<F>(&self, addr: Ipv4Addr, port: u16, read_cb: F) -> u64
    where F: Fn(CrossPacket, Ipv4Addr, u16) + 'static,
    {
        let sock = Arc::new(UdpSocket::new(
            self.fd.fetch_add(1, Ordering::AcqRel),
            self.pkt_out.clone(),
            addr,
            port,
            Box::new(read_cb),
        ));

        self.sockets.put(port as u64, Arc::clone(&sock));

        port as u64
    }

    /// Closes the given socket
    pub fn close(&self, socket: u64) {
        self.sockets.remove(socket);
    }
}

pub struct UdpSocket {
    fd: u64,
    read_cb: PacketCallback,
    pkt_out: Sender<Packet<R2P2Header, EmptyMetadata>>,
    src: Ipv4Addr,
    src_port: u16,
}

unsafe impl Send for UdpSocket {}
unsafe impl Sync for UdpSocket {}

pub type PacketCallback = Box<Fn(CrossPacket, Ipv4Addr, u16)>;

impl UdpSocket {
    fn new(fd: u64, producers: Sender<Packet<R2P2Header, EmptyMetadata>>,
           src: Ipv4Addr,
           src_port: u16,
           read_cb: PacketCallback) -> UdpSocket
    {
        UdpSocket {
            fd,
            read_cb,
            src,
            src_port,
            pkt_out: producers,
        }
    }

    /// Send the content of the given packet out through the NIC
    #[inline]
    pub fn send(&self, pkt: &CrossPacket,
                addr: &Ipv4Addr,
                port: u16,
                add: R2P2Header)
    {
        let len = pkt.length();
        let mut ip: IpHeader = IpHeader::new();
        let mut udp: UdpHeader = UdpHeader::new();
        let mut mac: MacHeader = MacHeader::new();

        // FIXME: MACs are hardcoded for now
        mac.dst = MacAddress::new(0xb8, 0xca, 0x3a, 0x69, 0xcc, 0x10);
        //mac.dst = MacAddress::new(0xa0, 0x36, 0x9f, 0x27, 0x3c, 0x16);
        mac.src = MacAddress::new(0xb8, 0xca, 0x3a, 0x69, 0xb8, 0x98);
        mac.set_etype(0x0800);

        ip.set_ttl(64);
        ip.set_version(4);
        ip.set_ihl(5);
        ip.set_length(pkt.length() + (UdpHeader::size() as u16) +
                      (R2P2Header::size() as u16) + IpHeader::size() as u16);
        ip.set_flags(2);
        ip.set_dst(u32::from(*addr));
        ip.set_src(u32::from(self.src));
        ip.set_protocol(17);
        ip.set_id(0x1234);

        let csum = self.checksum(&ip);
        ip.set_csum(csum);

        udp.set_checksum(0);
        udp.set_length(pkt.length() + R2P2Header::size() as u16 +
                       UdpHeader::size() as u16);
        udp.set_src_port(self.src_port);
        udp.set_dst_port(port);

        let upkt = pkt.as_segment();
        let upkt = upkt.push_header(&mac).unwrap()
            .push_header(&ip).unwrap()
            .push_header(&udp).unwrap()
            .push_header(&add).unwrap();

        self.pkt_out.send(upkt).unwrap();
    }

    pub fn checksum(&self, p: &IpHeader) -> u16
    {
        unsafe {
            let ptr = p as *const IpHeader;
            let bytes = mem::transmute::<*const IpHeader, *mut u8>(p);
            ipv4_cksum(bytes) as u16
        }
    }

    /// Delivers a set of packets to this socket, i.e. calls the read_cb
    /// registered by user
    #[inline]
    fn deliver(&self, mut pkt: CrossPacket,
               src_addr: Ipv4Addr,
               src_port: u16)
    {
        (self.read_cb)(pkt, src_addr, src_port);
    }
}

struct UdpSender<T>
where T: PacketTx + Clone + 'static
{
    input: Receiver<Packet<R2P2Header, EmptyMetadata>>,
    port: T,
}

impl<T> UdpSender<T>
where T: PacketTx + Clone + 'static
{
    fn new(input: Receiver<Packet<R2P2Header, EmptyMetadata>>,
           port: T) -> UdpSender<T>
    {
        UdpSender{
            input,
            port,
        }
    }
}

impl<T> Executable for UdpSender<T>
where T: PacketTx + Clone + 'static
{
    fn execute(&mut self) {
        // FIXME: send batches of dynamic sizes?
        let mut pkts = Vec::with_capacity(16);

        while let Ok(pkt) = self.input.try_recv() {
            pkts.push(unsafe { pkt.get_mbuf() });
        }

        let pkt_count = pkts.len() as u32;

        if pkt_count == 0 {
            return;
        }

        match self.port.send(&mut pkts) {
            Ok(count) => {
                if count != pkt_count {
                    println!("sent less packets than expected (expected {}, sent {})",
                             pkt_count, count);
                }
                mem::forget(pkts); // DPDK should free the vector now
            },
            Err(err) => println!("failed to send packets: {}", err),
        }
    }

    fn dependencies(&mut self) -> Vec<usize> {
        vec![]
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        println!("socket {}:{} closed", self.src, self.src_port);
    }
}
