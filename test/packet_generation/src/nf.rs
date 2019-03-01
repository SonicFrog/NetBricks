extern crate logmap;

use self::logmap::LoanMap;

use super::r2p2::R2P2Header;
use e2d2::common::EmptyMetadata;
use e2d2::headers::*;
use e2d2::interface::*;
use e2d2::native::zcsi::ipv4_cksum;
use e2d2::operators::{Batch, ReceiveBatch};
use e2d2::scheduler::{Executable, Scheduler};

use std::boxed::Box;
use std::mem;
use std::net::Ipv4Addr;
use std::result::Result;
use std::sync::Arc;
use std::sync::mpsc::{channel, Receiver, Sender};

pub type Socket = u16;

/// A NetBricks UDP stack
pub struct UdpStack {
    // all opened sockets are contained in this map
    sockets: LoanMap<Socket, Arc<UdpSocket>>,

    // ARP cache for outgoing packets
    macs: Arc<LoanMap<Ipv4Addr, MacAddress>>,

    // Sending end of the packet pipeline
    pkt_out: Sender<Packet<R2P2Header, EmptyMetadata>>,
}

impl UdpStack {
    fn setup_udp_recv<T, S>(ports: Vec<T>, sched: &mut S) -> Arc<UdpStack>
    where
        T: PacketRx + PacketTx + Clone + 'static,
        S: Scheduler + Sized,
    {
        println!("Setting up UDP recv pipelines...");

        let stack = Arc::new(UdpStack::new(ports.clone(), sched));
        let ret = Arc::clone(&stack);

        // Receiving setup
        let recv_pipeline = ports.iter().map(|port| {
            let stack = Arc::clone(&stack);

            ReceiveBatch::new(port.clone())
                .parse::<MacHeader>()
                .metadata(box move |pkt| pkt.get_header().src.clone())
                .parse::<IpHeader>()
                .metadata(box move |pkt| {
                    // keep the source ip around for later replies
                    let addr = pkt.get_header().src();
                    let mac = pkt.read_metadata().clone();

                    (addr, mac)
                })
                .parse::<UdpHeader>()
                .map(box move |pkt| {
                    let md = pkt.read_metadata();
                    let mac = md.1.clone();
                    let addr = Ipv4Addr::from(md.0);
                    let port = pkt.get_header().dst_port();

                    stack.macs.put(addr, mac);

                    stack.sockets.get(&port).map(|sock| {
                        let mut tmp = CrossPacket::from(pkt);
                        let len = IpHeader::size() + MacHeader::size() +
                            UdpHeader::size();
                        let src_port = pkt.get_header().src_port();

                        tmp.remove_data_head(len);

                        sock.deliver(tmp, addr, src_port);
                    });
                })
                .compose()
        });

        for pipeline in recv_pipeline {
            sched.add_task(pipeline).expect(
                "failed to setup recv pipeline",
            );
        }

        println!("UDP receiver setup done!");

        ret
    }

    /// Runs a new stack on the given scheduler utilizing the given `PortQueue`s
    /// The user provides a setup function that is executed on the resulting
    /// UdpStack after creation
    pub fn run_stack_on<F, T, S, V>(
        ports: Vec<T>,
        sched: &mut S,
        setup: F,
    ) -> (Arc<UdpStack>, V)
    where
        F: FnOnce(&Arc<UdpStack>) -> V + 'static,
        T: PacketRx + PacketTx + Clone + 'static,
        S: Scheduler + Sized,
        V: Sized,
    {
        let stack = UdpStack::setup_udp_recv(ports, sched);
        let result = setup(&stack);

        (stack, result)
    }

    pub fn socket_for(&self, sock: Socket) -> Arc<UdpSocket> {
        self.sockets.get(&sock).unwrap().clone()
    }

    /// Creates a new UDPStack on the given scheduler using the given `PortQueue`s
    pub fn new<T, S>(ports: Vec<T>, sched: &mut S) -> UdpStack
    where
        T: PacketRx + PacketTx + Clone + 'static,
        S: Scheduler + Sized,
    {
        if ports.len() > 1 {
            println!("using more than one TX ring is currently unsupported");
        }

        let (send, recv) = channel();

        let stack = UdpStack {
            sockets: LoanMap::with_capacity(65536, 1),
            macs: Arc::new(LoanMap::with_capacity(65536, 1)),
            pkt_out: send,
        };

        sched
            .add_task(UdpSender::new(recv, ports[0].clone()))
            .expect("failed to setup udp sending");

        stack
    }

    /// Binds a new socket on this UDPStack
    pub fn bind<F>(&self, addr: Ipv4Addr, port: u16, read_cb: F) -> Socket
    where
        F: Fn(CrossPacket, Ipv4Addr, u16) + 'static,
    {
        let macs = Arc::clone(&self.macs);

        let sock = Arc::new(UdpSocket::new(
            self.pkt_out.clone(),
            macs,
            addr,
            port,
            Box::new(read_cb),
        ));

        self.sockets.put(port, Arc::clone(&sock));

        port
    }
}

unsafe impl Send for UdpStack {}
unsafe impl Sync for UdpStack {}

pub struct UdpSocket {
    read_cb: PacketCallback,
    pkt_out: Sender<Packet<R2P2Header, EmptyMetadata>>,
    src: Ipv4Addr,
    src_port: u16,
    macs: Arc<LoanMap<Ipv4Addr, MacAddress>>,
}

unsafe impl Send for UdpSocket {}
unsafe impl Sync for UdpSocket {}

pub type PacketCallback = Box<Fn(CrossPacket, Ipv4Addr, u16)>;

impl UdpSocket {
    fn new(
        producers: Sender<Packet<R2P2Header, EmptyMetadata>>,
        macs: Arc<LoanMap<Ipv4Addr, MacAddress>>,
        src: Ipv4Addr,
        src_port: u16,
        read_cb: PacketCallback,
    ) -> UdpSocket {
        UdpSocket {
            read_cb: read_cb,
            src: src,
            src_port: src_port,
            macs: macs,
            pkt_out: producers,
        }
    }

    /// Send the content of the given packet out through the NIC
    #[inline]
    pub fn send(
        &self,
        pkt: &CrossPacket,
        addr: &Ipv4Addr,
        port: u16,
        // TODO: generalize additional header
        add: R2P2Header,
    ) -> Result<usize, ()> {
        let mut ip: IpHeader = IpHeader::new();
        let mut udp: UdpHeader = UdpHeader::new();
        let mut mac: MacHeader = MacHeader::new();

        if let Some(mac_dst) = self.macs.get(addr) {
            mac.dst = mac_dst.clone();
        } else {
            return Err(());
        }

        // FIXME: MAC source is hardcoded for now
        mac.src = MacAddress::new(0xb8, 0xca, 0x3a, 0x69, 0xb8, 0x98);
        mac.set_etype(0x0800);

        let hdr_len = UdpHeader::size() + R2P2Header::size() + IpHeader::size();

        ip.set_ttl(64);
        ip.set_version(4);
        ip.set_ihl(5);
        ip.set_length(pkt.length() + hdr_len as u16);
        ip.set_flags(2);
        ip.set_dst(u32::from(*addr));
        ip.set_src(u32::from(self.src));
        ip.set_protocol(17);
        ip.set_id(0x1234);

        let csum = self.checksum(&ip);
        ip.set_csum(csum);

        udp.set_checksum(0);
        udp.set_length(
            pkt.length() + R2P2Header::size() as u16 + UdpHeader::size() as u16,
        );
        udp.set_src_port(self.src_port);
        udp.set_dst_port(port);

        let upkt = pkt.as_segment();
        let upkt = upkt.push_header(&mac)
            .unwrap()
            .push_header(&ip)
            .unwrap()
            .push_header(&udp)
            .unwrap()
            .push_header(&add)
            .unwrap();

        self.pkt_out.send(upkt).unwrap();

        Ok(pkt.length() as usize)
    }

    pub fn checksum(&self, p: &IpHeader) -> u16 {
        unsafe {
            let bytes = mem::transmute::<*const IpHeader, *mut u8>(p);
            ipv4_cksum(bytes) as u16
        }
    }

    /// Delivers a set of packets to this socket, i.e. calls the read_cb
    /// registered by user
    fn deliver(&self, pkt: CrossPacket, src_addr: Ipv4Addr, src_port: u16) {
        (self.read_cb)(pkt, src_addr, src_port);
    }
}

struct UdpSender<T>
where
    T: PacketTx + Clone + 'static,
{
    input: Receiver<Packet<R2P2Header, EmptyMetadata>>,
    port: T,
}

impl<T> UdpSender<T>
where
    T: PacketTx + Clone + 'static,
{
    fn new(
        input: Receiver<Packet<R2P2Header, EmptyMetadata>>,
        port: T,
    ) -> UdpSender<T> {
        UdpSender { input, port }
    }
}

impl<T> Executable for UdpSender<T>
where
    T: PacketTx + Clone + 'static,
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
                    println!(
                        "sent less packets than expected (expected {}, sent {})",
                        pkt_count,
                        count
                    );
                }
                mem::forget(pkts); // DPDK should free the vector now
            }
            Err(err) => println!("failed to send packets: {}", err),
        }
    }

    fn dependencies(&mut self) -> Vec<usize> {
        // this depends on nothing
        vec![]
    }
}
