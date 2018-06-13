extern crate e2d2;
extern crate logmap;

use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::ops::Index;
use std::slice::Iter;
use std::sync::Arc;

use e2d2::common::EmptyMetadata;
use e2d2::headers::{EndOffset, NullHeader, UdpHeader};
use e2d2::interface::*;
use e2d2::scheduler::Scheduler;

use logmap::LoanMap;

use super::nf::{UdpSocket, UdpStack};

#[derive(Default)]
#[repr(C, packed)]
pub struct R2P2Header {
    magic: u8,
    hdr_sz: u8,
    policy_type: u8,
    flags: u8,
    req_id: u16,
    pkt_id: u16,
}

impl fmt::Display for R2P2Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "policy {} flags {} req_id {} pkt_id {}",
            self.policy_type,
            self.flags,
            self.req_id,
            self.pkt_id,
        )
    }
}

impl EndOffset for R2P2Header {
    type PreviousHeader = UdpHeader;

    #[inline]
    fn offset(&self) -> usize {
        8 // header is 8 bytes
    }

    #[inline]
    fn size() -> usize {
        8
    }

    #[inline]
    fn payload_size(&self, packet_size: usize)  -> usize {
        packet_size - self.offset()
    }

    #[inline]
    fn check_correct(&self, _prev: &UdpHeader) -> bool {
        true
    }
}

impl R2P2Header {
    #[inline]
    pub fn new() -> R2P2Header {
        Default::default()
    }

    #[inline]
    pub fn req_id(&self) -> u16 {
        self.req_id
    }

    #[inline]
    pub fn set_req_id(&mut self, req_id: u16) {
        self.req_id = req_id;
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn message_type(&self) -> u8 {
        (self.policy_type & 0xF) >> 4
    }

    #[inline]
    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags
    }

    #[inline]
    pub fn pkt_id(&self) -> u16 {
        self.pkt_id
    }

    #[inline]
    pub fn set_pkt_id(&self, pkt_id: u16) {
        self.pkt_id = pkt_id
    }

    #[inline]
    pub fn magic(&self) -> u8 {
        self.magic
    }

    #[inline]
    pub fn hdr_size(&self) -> u8 {
        self.hdr_sz
    }

    #[inline]
    pub fn set_hdr_size(&mut self, sz: u8) {
        self.hdr_sz = sz
    }
}

pub type RequestCB = Box<Fn(&R2P2Request) -> R2P2Response>;

enum MessageType {
    Part = 0,
    Ack = 1,
}

impl TryFrom<u8> for MessageType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Part),
            1 => Ok(MessageType::Ack),
            _ => Err(value),
        }
    }
}

#[derive(PartialEq, Hash)]
struct RequestId {
    id: u16,
    addr: u32,
    port: u16,
}

impl RequestId {
    fn src_addr(&self) -> u32 {
        self.addr
    }

    fn src_port(&self) -> u16 {
        self.port
    }

    fn req_id(&self) -> u16 {
        self.id
    }
}

pub struct R2P2Server<T, S>
    where T: PacketTx + PacketRx + Clone + 'static,
          S: Scheduler + Sized,
{
    /// requests which aren't complete
    pending_reqs: LoanMap<RequestId, R2P2Request>,
    /// responses which haven't been ack'ed yet
    pending_resps: LoanMap<RequestId, R2P2Response>,

    /// the socket this server runs on
    socket: Arc<UdpSocket>,
    /// the application callback for processing incoming requests
    request_cb: RequestCB,

    phantom_s: PhantomData<S>,
    phantom_t: PhantomData<T>,
}

impl<T, S> R2P2Server<T, S>
    where T: PacketTx + PacketRx + Clone + 'static,
          S: Scheduler + Sized + 'static,
{
    pub fn new(ports: Vec<T>,
               sched: &mut S,
               request_cb: RequestCB,
               addr: Ipv4Addr,
               port: u16) -> R2P2Server<T, S>
    {
        let mut outer_socket;
        let mut server: R2P2Server<T, S>;

        let mut packet_cb = |pkt: &Packet<UdpHeader, u32>, src, src_port| {
            let pkt = pkt.parse_header::<R2P2Header>();

            server.udp_in(&pkt, src, src_port)
        };

        let stack_setup = |stack: &UdpStack<T>| {
            outer_socket = stack.bind(addr, port, packet_cb);

            Ok(())
        };

        server = R2P2Server {
            pending_reqs: LoanMap::new(),
            pending_resps: LoanMap::new(),
            socket: outer_socket,
            request_cb: request_cb,
            phantom_s: PhantomData,
            phantom_t: PhantomData,
        };

        UdpStack::run_stack_on(ports, sched, stack_setup);

        server
    }

    fn udp_in(&self, pkt: &Packet<R2P2Header, u32>,
              src: Ipv4Addr,
              src_port: u16)
    {
        let req_id = RequestId {
            id: pkt.get_header().req_id(),
            addr: u32::from(src),
            port: src_port,
        };
        let msg_type = match MessageType::try_from(pkt.get_header().message_type()) {
            Err(num) => {
                println!("unknown message type {}", num);
                return;
            },
            Ok(tpe) => tpe,
        };

        match msg_type {
            MessageType::Ack => self.acked(req_id),

            MessageType::Part => {
                if let Some(&mut request) = self.pending_reqs.get_mut(req_id) {
                    // we have already received some packets for this request
                    request.insert(*pkt.clone());

                    if request.is_complete() {
                        self.process(&request, src, src_port);
                        self.pending_reqs.remove(req_id);
                    }
                } else {
                    // this is the first packet we receive for this request
                    if !R2P2Request::is_first(&pkt) {
                        println!("out-of-order packet delivery");
                        return;
                    }
                    let req = R2P2Request::new(pkt, src_port);

                    if req.is_complete() {
                        self.process(&req, src, src_port);
                    } else {
                        self.pending_reqs.put(req_id, req);
                    }
                }
            },
        }
    }

    #[inline]
    fn process(&self, req: &R2P2Request, addr: Ipv4Addr, port: u16) {
        let resp = (self.request_cb)(&req);
        self.udp_out(resp, addr, port);
    }

    #[inline]
    fn udp_out(&self, resp: R2P2Response, addr: Ipv4Addr, port: u16) -> Result<(), ()> {
        self.socket.send_many(&resp.pkts, &addr, port);
        Ok(())
    }

    #[inline]
    fn acked(&self, resp: RequestId) {
        self.pending_resps.remove(resp);
    }
}

struct R2P2Request {
    id: RequestId,
    msgs: Vec<Packet<R2P2Header, u32>>,
}

impl R2P2Request {
    fn new(first: &Packet<R2P2Header, u32>, src_port: u16) -> R2P2Request {
        assert!(R2P2Request::is_first(first));

        // avoid resizing by allocating all we need right now
        let mut msgs = Vec::with_capacity(first.get_header().pkt_id() as usize);
        // TODO: check that this does not actually copy the data
        msgs[0] = *first.clone();

        let hdr = first.get_header();

        let id = RequestId {
            id: hdr.req_id(),
            addr: *first.read_metadata(),
            port: src_port,
        };

        R2P2Request {
            id: id,
            msgs: msgs,
        }
    }

    #[inline]
    fn is_first(pkt: &Packet<R2P2Header, u32>) -> bool {
        pkt.get_header().flags() != 0
    }

    #[inline]
    fn insert(&mut self, pkt: &Packet<R2P2Header, u32>) {
        let idx = pkt.get_header().pkt_id() as usize;

        if idx >= self.msgs.capacity() {
            println!("unexpected packet in request");
            return;
        }

        self.msgs[idx] = *pkt.clone();
    }

    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.id.src_addr())
    }

    pub fn src_port(&self) -> u16 {
        self.id.src_port()
    }

    #[inline]
    pub fn is_complete(&self) -> bool {
        if self.msgs.len() == 0 {
            false
        } else {
            self.msgs.len() == self.msgs.capacity()
        }
    }
}

impl Index<usize> for R2P2Request {
    type Output = u8;

    fn index(&self, idx: usize) -> &Self::Output {
        let mut pkt_idx = 0;
        let mut byte_idx = 0;

        loop {
            if pkt_idx >= self.msgs.len() {
                panic!("out of bound access in request");
            }

            if idx < byte_idx {
                let pkt = self.msgs[pkt_idx];
                let index = idx % pkt.get_payload().len();

                return &pkt.get_payload()[index];
            } else {
                byte_idx += self.msgs[pkt_idx].get_payload().len();
                pkt_idx += 1;
            }
        }
    }
}

pub struct R2P2Response {
    pkts: Vec<Packet<NullHeader, EmptyMetadata>>,
}

impl R2P2Response {
    #[inline]
    pub fn new(pkts: Vec<Packet<NullHeader, EmptyMetadata>>,
               dst: Ipv4Addr, dst_port: u16) -> R2P2Response
    {
        for pkt in pkts {
             // TODO: create correct R2P2 header
        }

        R2P2Response {
            pkts,
        }
    }

    pub fn iter(&self) -> Iter<Packet<NullHeader, EmptyMetadata>> {
        self.pkts.iter()
    }
}
