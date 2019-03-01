extern crate e2d2;
extern crate logmap;


use super::nf::UdpStack;

use e2d2::headers::{EndOffset, UdpHeader};
use e2d2::interface::*;
use e2d2::scheduler::Scheduler;

use logmap::OptiMap;
use std::collections::hash_map::RandomState;
use std::convert::TryFrom;
use std::fmt;
use std::mem::{size_of, forget};
use std::net::Ipv4Addr;
use std::ptr;
use std::slice::Iter;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicPtr, Ordering};

const FIRST_FLAG: u8 = 0x80;

#[derive(Default, Clone, Copy)]
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
            "policy 0x{:02x} flags 0x{:02x} req_id 0x{:04x} pkt_id 0x{:04x}",
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
    fn payload_size(&self, packet_size: usize) -> usize {
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

    pub fn set_type(&mut self, tp: u8) {
        self.policy_type = tp & 0xF;
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
    pub fn set_pkt_id(&mut self, pkt_id: u16) {
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

pub type RequestCB = Box<Fn(R2P2Request) -> R2P2Response>;

#[repr(u8)]
enum MessageType {
    Request = 0,
    Response = 1,
    Ack = 3,
}

impl TryFrom<u8> for MessageType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Request),
            1 => Ok(MessageType::Response),
            3 => Ok(MessageType::Ack),
            _ => Err(value),
        }
    }
}

#[derive(PartialEq, Hash, Clone)]
pub struct RequestId {
    id: u16,
    addr: u32,
    port: u16,
}

impl RequestId {
    pub fn src_addr(&self) -> u32 {
        self.addr
    }

    pub fn src_port(&self) -> u16 {
        self.port
    }

    pub fn req_id(&self) -> u16 {
        self.id
    }
}

pub struct R2P2Server {
    /// requests which aren't complete
    pending_reqs: OptiMap<RequestId, R2P2Request, RandomState>,
    /// responses which haven't been ack'ed yet
    pending_resps: OptiMap<RequestId, R2P2Response, RandomState>,

    /// the udp stack we run on
    stack: AtomicPtr<UdpStack>,
    /// the socket this server runs on
    socket: AtomicU16,
    /// the application callback for processing incoming requests
    request_cb: RequestCB,
}

impl R2P2Server {
    pub fn new<T, S>(
        ports: Vec<T>,
        sched: &mut S,
        request_cb: RequestCB,
        addr: Ipv4Addr,
        port: u16,
    ) -> Arc<R2P2Server>
    where
        T: PacketTx + PacketRx + Clone + 'static,
        S: Scheduler + Sized + 'static,
    {
        let srv = Arc::new(R2P2Server {
            pending_reqs: OptiMap::new(),
            pending_resps: OptiMap::new(),
            socket: AtomicU16::new(0),
            stack: AtomicPtr::new(ptr::null_mut()),
            request_cb: request_cb,
        });
        let clone = Arc::clone(&srv);
        let clone2 = Arc::clone(&srv);

        let packet_cb = move |pkt: CrossPacket, addr, port| {
            clone.udp_in(pkt, addr, port)
        };

        // TODO: rewrite init logic (will probably need NetBricks edits)
        let stack_setup = move |stack: &Arc<UdpStack>| {
            let socket = stack.bind(addr, port, packet_cb);

            clone2.socket.store(socket, Ordering::Relaxed);
            clone2.stack.store(
                Arc::into_raw(Arc::clone(stack)) as *mut _,
                Ordering::Relaxed,
            );

            0
        };

        UdpStack::run_stack_on(ports, sched, stack_setup);

        srv
    }

    #[inline]
    fn udp_in(&self, mut pkt: CrossPacket, src: Ipv4Addr, src_port: u16) {
        let header = pkt.get_header::<R2P2Header>().clone();

        pkt.remove_data_head(R2P2Header::size());

        let req_id = RequestId {
            id: header.req_id(),
            addr: u32::from(src),
            port: src_port,
        };
        let msg_type = match MessageType::try_from(header.message_type()) {
            Err(num) => {
                println!("unknown message type {}", num);
                return;
            }
            Ok(tpe) => tpe,
        };

        match msg_type {
            MessageType::Ack => self.acked(req_id),

            MessageType::Request => {
                // TODO: better request processing
                if let Some(request) = self.pending_reqs.get(&req_id) {
                    let mut new_req = request.clone();
                    // we have already received some packets for this request
                    new_req.insert(pkt, header);

                    if request.is_complete() {
                        self.process(new_req, src, src_port);
                        self.pending_reqs.delete(&req_id);
                    } else {
                        self.pending_reqs.put(req_id, new_req);
                    }
                } else {
                    // this is the first packet we receive for this request
                    if !R2P2Request::is_first(&header) {
                        println!("out-of-order packet delivery");
                        return;
                    }
                    let req = R2P2Request::new(pkt, header, src, src_port);

                    if req.is_complete() {
                        self.process(req, src, src_port);
                    } else {
                        self.pending_reqs.put(req_id, req);
                    }
                }
            }
            MessageType::Response => {
                println!("client sent a response message");
                return;
            }
        }
    }

    #[inline]
    fn process(&self, req: R2P2Request, addr: Ipv4Addr, port: u16) {
        let resp = (self.request_cb)(req);

        self.udp_out(resp, addr, port).unwrap();
    }

    #[inline]
    fn udp_out(
        &self,
        resp: R2P2Response,
        addr: Ipv4Addr,
        port: u16,
    ) -> Result<(), ()> {
        // TODO: rewrite init logic to avoid atomics here
        let socket = self.socket.load(Ordering::Relaxed);
        let stack =
            unsafe { Arc::from_raw(self.stack.load(Ordering::Relaxed)) };
        let socket = stack.socket_for(socket);
        let mut i = 0;

        resp.iter().for_each(|p| {
            let mut header = R2P2Header::new();

            if i == 0 {
                header.set_flags(FIRST_FLAG);
            }

            header.set_type(1);
            header.set_req_id(resp.req_id.id);
            header.set_pkt_id(i);

            i += 1;

            socket.send(p, &addr, port, header).expect(
                "failed to send packets",
            );
        });

        forget(stack);
        Ok(())
    }

    #[inline]
    fn acked(&self, resp: RequestId) {
        self.pending_resps.delete(&resp);
    }
}

pub struct R2P2Request {
    id: RequestId,
    msgs: Vec<CrossPacket>,
}

impl R2P2Request {
    fn new(
        first: CrossPacket,
        header: R2P2Header,
        src_addr: Ipv4Addr,
        src_port: u16,
    ) -> R2P2Request {
        debug_assert!(R2P2Request::is_first(&header));
        debug_assert!(header.pkt_id() >= 1);

        // avoid resizing by allocating all we need right now
        let mut msgs = Vec::with_capacity(header.pkt_id() as usize);
        let id = RequestId {
            id: header.req_id(),
            addr: u32::from(src_addr),
            port: src_port,
        };

        msgs.push(first);

        R2P2Request { id: id, msgs: msgs }
    }

    #[inline]
    fn is_first(header: &R2P2Header) -> bool {
        (header.flags() & FIRST_FLAG) != 0
    }

    #[inline]
    fn insert(&mut self, mut pkt: CrossPacket, header: R2P2Header) {
        let idx = header.pkt_id() as usize;

        if idx >= self.msgs.capacity() {
            println!("unexpected packet in request");
            return;
        }

        pkt.remove_data_head(size_of::<R2P2Header>());

        self.msgs.push(pkt);
    }

    pub fn pkts(&self) -> &Vec<CrossPacket> {
        &self.msgs
    }

    pub fn id(&self) -> &RequestId {
        &self.id
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

impl Clone for R2P2Request {
    fn clone(&self) -> Self {
        R2P2Request {
            id: self.id.clone(),
            msgs: self.msgs.clone(),
        }
    }
}

pub struct R2P2Response {
    pkts: Vec<CrossPacket>,
    req_id: RequestId,
}

impl R2P2Response {
    #[inline]
    pub fn new(pkts: Vec<CrossPacket>, req_id: RequestId) -> R2P2Response {
        R2P2Response {
            req_id: req_id,
            pkts: pkts,
        }
    }

    pub fn iter(&self) -> Iter<CrossPacket> {
        self.pkts.iter()
    }
}
