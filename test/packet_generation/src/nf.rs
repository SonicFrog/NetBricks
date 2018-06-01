extern crate logmap;

use e2d2::common::*;
use e2d2::headers::*;
use e2d2::interface::*;
use e2d2::operators::*;
use e2d2::queues::{new_mpsc_queue_pair, MpscProducer};
use e2d2::scheduler::Scheduler;
use e2d2::native::zcsi::MBuf;

use std::boxed::Box;
use std::result::Result;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use self::logmap::LoanMap;

pub type Socket = u16;

#[derive(Clone)]
pub struct UdpStack<T>
    where
    T: PacketRx + PacketTx + Clone + 'static,
{
    // the last fd for the last opened socket
    fd: Arc<AtomicU64>,
    // all opened sockets are contained in this map
    sockets: Arc<LoanMap<Socket, Arc<UdpSocket>>>,
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

struct Udp4SocketID {
    addr: Ipv4Addr,
    port: u16,
}

impl SocketID for Udp4SocketID {
    type Addr = Ipv4Addr;
    type Port = u16;

    fn addr(&self) -> Self::Addr {
        self.addr
    }

    fn port(&self) -> Self::Port {
        self.port
    }
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
                    // .filter(box move |pkt| {
                    //     ports.iter().any(|port| port.mac_address() == pkt.get_header().dst)
                // })
                // FIXME: the port here is an abstract one so it doesn't have a MAC
                    .parse::<IpHeader>()
                    .transform(box move |pkt|{
                        let src = pkt.get_header().src();
                        pkt.write_metadata(&src).unwrap();
                    })
                    .parse::<UdpHeader>()
                    .map(box move |pkt| {
                        let port = pkt.get_header().dst_port();
                        stack.sockets.get(&port).map(|sock| sock.deliver(pkt));
                    })
                    .compose()
            });

        for pipeline in recv_pipeline  {
            sched.add_task(pipeline);
        }

        println!("UDP receiver setup done!");

        ret
    }

    pub fn run_stack_on<F, S>(ports: Vec<T>, sched: &mut S, setup: F) -> Arc<UdpStack<T>>
        where F: Fn(&UdpStack<T>) -> Result<(), String> + Send + Sync + 'static,
              S: Scheduler + Sized,
    {
        let stack = UdpStack::setup_udp_recv(ports, sched);

        if let Err(err) = setup(&*stack) {
            println!("setup function failed to run: {}", err);
        }

        stack
    }

    pub fn new<S>(ports: Vec<T>, sched: &mut S) -> UdpStack<T>
        where S: Scheduler + Sized,
    {
        let mut producers = Vec::new();

        for port in &ports {
            let (tx, rx) = new_mpsc_queue_pair();

            producers.push(tx);
            sched.add_task(rx.send(port.clone()));
        }

        UdpStack {
            fd: Arc::new(AtomicU64::new(0)),
            producers: producers,
            ports: ports.clone(),
            sockets: Arc::new(LoanMap::with_capacity(65536, 1)),
        }
    }

    pub fn bind<F>(&self, addr: Ipv4Addr, port: u16, read_cb: F) -> Arc<UdpSocket>
        where F: Fn(&[u8], Ipv4Addr, u16) + 'static
    {
        let sock = Arc::new(UdpSocket{
            src: addr,
            src_port: port,
            last_out: 0,
            read_cb: Box::new(read_cb),
            producers: self.producers.clone(),
        });

        self.sockets.put(port, Arc::clone(&sock));

        sock
    }

    pub fn close(&self, socket: u16) {
        self.sockets.remove(socket);
    }
}


pub struct UdpSocket {
    read_cb: Box<Fn(&[u8], Ipv4Addr, u16)>,
    producers: Vec<MpscProducer>,
    src: Ipv4Addr,
    src_port: u16,
    last_out: usize,
}

unsafe impl Send for UdpSocket {}
unsafe impl Sync for UdpSocket {}

impl UdpSocket {
    /// Aimed for use with raw mbufs to avoid copying data around
    pub fn send(&self, data: *const MBuf, addr: &Ipv4Addr, port: u16) {
        let mut ip: IpHeader = IpHeader::new();
        let mut udp: UdpHeader = UdpHeader::new();
        let mac: MacHeader = MacHeader::new();
        let pkt: Packet<NullHeader, EmptyMetadata> = unsafe {
            packet_from_mbuf(data as *mut MBuf, 0)
        };

        ip.set_src(u32::from(self.src));
        ip.set_dst(u32::from(*addr));
        udp.set_src_port(self.src_port);
        udp.set_dst_port(port);

        let pkt = pkt.push_header(&mac).unwrap()
            .push_header(&ip).unwrap()
            .push_header(&udp).unwrap();

        // TODO: use round robin to select output port
        // TODO: supports sending with scatter gather
        self.producers[self.last_out].enqueue_one(pkt);
    }

    /// Delivers a set of packets to this socket
    /// Returns the number of bytes sent on the NIC
    fn deliver(&self, pkt: &Packet<UdpHeader, EmptyMetadata>) -> usize {
        let bytes = pkt.get_payload();

        (self.read_cb)(bytes, self.src, self.src_port);
        bytes.len()
    }
}
