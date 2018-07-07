extern crate logmap;

use e2d2::headers::*;
use e2d2::interface::*;
use e2d2::operators::{Batch, ReceiveBatch};
use e2d2::queues::{new_mpsc_queue_pair, MpscProducer};
use e2d2::scheduler::Scheduler;

use std::boxed::Box;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::result::Result;
use std::sync::atomic::{AtomicU64, Ordering};

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
    // producers each sending to a different port
    producers: Vec<MpscProducer>,
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
                            let tmp = CrossPacket::from(pkt);
                            sock.deliver(tmp, addr, port as u16)
                        });
                    })
                    .compose()
            });

        for pipeline in recv_pipeline  {
            sched.add_task(pipeline)
                .expect("failed to add task to pipeline");
        }

        println!("UDP receiver setup done!");

        ret
    }

    /// Runs a new stack on the given scheduler utilizing the given `PortQueue`s
    /// The user provides a setup function that is executed on the resulting
    /// UdpStack after creation
    pub fn run_stack_on<F, S>(ports: Vec<T>, sched: &mut S, setup: F) -> Arc<UdpStack<T>>
    where F: FnOnce(&UdpStack<T>) -> Result<(), String> + 'static,
          S: Scheduler + Sized,
    {
        let stack = UdpStack::setup_udp_recv(ports, sched);

        if let Err(err) = setup(&*stack) {
            println!("setup function failed to run: {}", err);
        }

        stack
    }

    /// Creates a new UDPStack on the given scheduler using the given `PortQueue`s
    pub fn new<S>(ports: Vec<T>, sched: &mut S) -> UdpStack<T>
    where S: Scheduler + Sized,
    {
        let mut producers = Vec::with_capacity(ports.len());

        for port in &ports {
            let (tx, rx) = new_mpsc_queue_pair();

            producers.push(tx);
            sched.add_task(rx.send(port.clone()))
                .expect("failed to setup sending on port {}");
        }

        UdpStack {
            fd: AtomicU64::new(0),
            producers: producers,
            ports: ports.clone(),
            sockets: LoanMap::with_capacity(65536, 1),
        }
    }

    /// Binds a new socket on this UDPStack
    pub fn bind<F>(&self, addr: Ipv4Addr, port: u16, read_cb: F) -> Arc<UdpSocket>
    where F: Fn(CrossPacket, Ipv4Addr, u16) + 'static,
    {
        let sock = Arc::new(UdpSocket::new(
            self.fd.fetch_add(1, Ordering::AcqRel),
            self.producers.clone(),
            addr,
            port,
            Box::new(read_cb),
        ));

        self.sockets.put(port as u64, Arc::clone(&sock));

        sock
    }

    /// Closes the given socket
    pub fn close(&self, socket: u64) {
        self.sockets.remove(socket);
    }
}

pub struct UdpSocket {
    fd: u64,
    read_cb: PacketCallback,
    producers: Vec<MpscProducer>,
    src: Ipv4Addr,
    src_port: u16,
}

unsafe impl Send for UdpSocket {}
unsafe impl Sync for UdpSocket {}

pub type PacketCallback = Box<Fn(CrossPacket, Ipv4Addr, u16)>;

impl UdpSocket {
    fn new(fd: u64, producers: Vec<MpscProducer>,
           src: Ipv4Addr,
           src_port: u16,
           read_cb: PacketCallback) -> UdpSocket
    {
        UdpSocket {
            fd,
            read_cb,
            src,
            src_port,
            producers,
        }
    }

    /// Send the content of the given packet out through the NIC
    #[inline]
    pub fn send(&self, pkt: &CrossPacket,
                addr: &Ipv4Addr,
                port: u16)
    {
        let len = pkt.length();
        let mut ip: IpHeader = IpHeader::new();
        let mut udp: UdpHeader = UdpHeader::new();
        let mut mac: MacHeader = MacHeader::new();

        // FIXME: MACs are hardcoded for now
        mac.src = MacAddress::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        mac.dst = MacAddress::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

        ip.set_ttl(128);
        ip.set_version(4);
        ip.set_ihl(5);
        ip.set_length(520);
        ip.set_dst(u32::from(*addr));

        udp.set_length(pkt.length());
        udp.set_src_port(self.src_port);
        udp.set_dst_port(port);

        let pkt = pkt.as_segment().to_packet();

        let pkt = pkt.push_header(&mac).unwrap()
            .push_header(&ip).unwrap()
            .push_header(&udp).unwrap();

        self.producers[0].enqueue_one(pkt);
    }

    /// Send many packets to the same destination out through the NIC
    pub fn send_many(&self, pkts: &Vec<CrossPacket>,
                     addr: &Ipv4Addr,
                     port: u16)
    {
        pkts.iter().for_each(|pkt| self.send(pkt, addr, port))
    }

    /// Delivers a set of packets to this socket, i.e. calls the read_cb registered by user
    #[inline]
    fn deliver(&self, mut pkt: CrossPacket,
               src_addr: Ipv4Addr,
               src_port: u16)
    {
        let hdr_len = IpHeader::size() + MacHeader::size() +
            UdpHeader::size();
        // remove headers from the data
        pkt.remove_data_head(hdr_len as u16);
        (self.read_cb)(pkt, src_addr, src_port);
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        println!("socket {}:{} closed", self.src, self.src_port);
    }
}
