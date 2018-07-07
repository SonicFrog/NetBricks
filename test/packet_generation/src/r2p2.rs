extern crate e2d2;
extern crate logmap;

use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;
use std::mem::{size_of, forget, uninitialized};
use std::net::Ipv4Addr;
use std::ptr;
use std::slice::Iter;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::channel;

use e2d2::headers::{EndOffset, UdpHeader};
use e2d2::interface::*;
use e2d2::scheduler::Scheduler;

use logmap::LoanMap;

use super::nf::{UdpSocket, UdpStack};

const FIRST_FLAG: u8 = 0x80;

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
               port: u16) -> Arc<R2P2Server<T, S>>
    {
        // FIXME: init is dirty
        let server: Arc<R2P2Server<T, S>> = Arc::new(unsafe {
            uninitialized()
        });
        let server_clone = Arc::clone(&server);
        let (tx, rx) = channel();

        // this callback should never run before function exits!!
        let packet_cb = move |pkt: CrossPacket, addr, port| {
            server_clone.udp_in(pkt, addr, port);
        };

        let stack_setup = move |stack: &UdpStack<T>| {
            let socket = stack.bind(addr, port, packet_cb);

            tx.send(socket).unwrap();

            Ok(())
        };

        UdpStack::run_stack_on(ports, sched, stack_setup);

        let mut srv = R2P2Server {
            pending_reqs: LoanMap::new(),
            pending_resps: LoanMap::new(),
            socket: rx.recv().unwrap(),
            request_cb: request_cb,
            phantom_s: PhantomData,
            phantom_t: PhantomData,
        };

        unsafe {
            let raw = Arc::into_raw(server)
                .offset((2 * size_of::<AtomicUsize>()) as isize);
            ptr::copy_nonoverlapping(raw, &mut srv as *mut R2P2Server<T, S>,
                                     size_of::<R2P2Server<T, S>>());
            forget(srv);
            Arc::from_raw(raw)
        }
    }

    fn udp_in(&self, pkt: CrossPacket, src: Ipv4Addr, src_port: u16)
    {
        let mut header: R2P2Header = unsafe { uninitialized() };
        pkt.get_header(&mut header);

        let req_id = RequestId {
            id: header.req_id(),
            addr: u32::from(src),
            port: src_port,
        };
        let msg_type = match MessageType::try_from(header.message_type()) {
            Err(num) => {
                println!("unknown message type {}", num);
                return;
            },
            Ok(tpe) => tpe,
        };

        match msg_type {
            MessageType::Ack => self.acked(req_id),

            MessageType::Request => {
                if let Some(mut request) = self.pending_reqs.get_mut(&req_id)
                {
                    // we have already received some packets for this request
                    request.insert(pkt, header);

                    if request.is_complete() {
                        self.process(request.clone(), src, src_port);
                        self.pending_reqs.remove(req_id);
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
            },
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
    fn udp_out(&self, resp: R2P2Response, addr: Ipv4Addr, port: u16) -> Result<(), ()> {
        resp.iter().for_each(|p| self.socket.send(p, &addr, port));
        Ok(())
    }

    #[inline]
    fn acked(&self, resp: RequestId) {
        self.pending_resps.remove(resp);
    }
}

unsafe impl<T, S> Sync for R2P2Server<T, S>
where T: PacketTx + PacketRx + Clone + 'static,
S: Scheduler + Sized + 'static {}

unsafe impl<T, S> Send for R2P2Server<T, S>
where T: PacketTx + PacketRx + Clone + 'static,
S: Scheduler + Sized + 'static {}

pub struct R2P2Request {
    id: RequestId,
    msgs: Vec<CrossPacket>,
}

impl R2P2Request {
    fn new(first: CrossPacket,
           header: R2P2Header,
           src_addr: Ipv4Addr,
           src_port: u16) -> R2P2Request
    {
        assert!(R2P2Request::is_first(&header));

        // avoid resizing by allocating all we need right now
        let mut msgs = Vec::with_capacity(header.pkt_id() as usize);
        let id = RequestId {
            id: header.req_id(),
            addr: u32::from(src_addr),
            port: src_port,
        };

        msgs[0] = first;

        R2P2Request {
            id: id,
            msgs: msgs,
        }
    }

    #[inline]
    fn is_first(header: &R2P2Header) -> bool {
        header.flags() == FIRST_FLAG
    }

    #[inline]
    fn insert(&mut self, mut pkt: CrossPacket, header: R2P2Header) {
        let idx = header.pkt_id() as usize;

        if idx >= self.msgs.capacity() {
            println!("unexpected packet in request");
            return;
        }

        pkt.remove_data_head(size_of::<R2P2Header>() as u16).unwrap();

        self.msgs[idx] = pkt;
    }

    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.id.src_addr())
    }

    pub fn src_port(&self) -> u16 {
        self.id.src_port()
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
    dst_addr: Ipv4Addr,
    dst_port: u16,
    req_id: RequestId,
}

impl R2P2Response {
    #[inline]
    pub fn new(pkts: Vec<CrossPacket>, dst: Ipv4Addr,
               dst_port: u16, req_id: RequestId) -> R2P2Response
    {
        R2P2Response {
            dst_addr: dst,
            dst_port: dst_port,
            req_id: req_id,
            pkts: pkts,
        }
    }

    pub fn iter(&self) -> Iter<CrossPacket> {
        self.pkts.iter()
    }
}
