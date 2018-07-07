extern crate logmap;

use std::collections::hash_map::RandomState;
use std::hash::{Hash, Hasher};
use std::mem;
use std::net::Ipv4Addr;
use std::str::from_utf8_unchecked;
use std::sync::Arc;

use super::r2p2::*;
use self::logmap::OptiMap;

use e2d2::scheduler::*;
use e2d2::interface::*;

pub struct RedisServer<T, S>
    where T: PacketTx + PacketRx + Clone + 'static,
          S: Scheduler + Sized + 'static,
{
    kv: OptiMap<String, RedisKVEntry, RandomState>,
    server: Arc<R2P2Server<T, S>>,
}

impl<T, S> RedisServer<T, S>
    where T: PacketTx + PacketRx + Clone + 'static,
          S: Scheduler + Sized + 'static,
{
    pub fn new(ports: Vec<T>,
               sched: &mut S,
               addr: Ipv4Addr,
               port: u16) -> Arc<RedisServer<T, S>>
    {
        println!("settings up redis server {}:{}", addr, port);

        let mut server: Arc<RedisServer<T, S>> = unsafe {
            mem::uninitialized()
        };

        let r2p2 = R2P2Server::new(ports, sched, box move |req| {
            let req_id = req.id().clone();
            let (key, entry) = RedisKVEntry::new(req);

            if let Some(kv) = entry {
                server.kv.put(key, kv);
                let mut pkt = CrossPacket::new_from_raw();
                pkt.add_data_head(4);

                {
                    let payload = pkt.get_mut_payload(0);

                    payload[0] = '"' as u8;
                    payload[1] = 'O' as u8;
                    payload[2] = 'K' as u8;
                    payload[3] = '"' as u8;
                }

                let mut resp = Vec::with_capacity(1);
                resp[0] = pkt;

                R2P2Response::new(resp, addr, port, req_id.clone())
            } else {
                if let Some(value) = server.kv.get(&key) {
                    R2P2Response::new(value.pkt.clone(),
                                      addr, port, req_id.clone())
                } else {
                    let mut pkt = CrossPacket::new_from_raw();
                    pkt.add_data_head(4);

                    {
                        let payload = pkt.get_mut_payload(0);

                        payload[0] = '"' as u8;
                        payload[1] = 'K' as u8;
                        payload[2] = 'O' as u8;
                        payload[3] = '"' as u8;
                    }

                    let mut resp = Vec::with_capacity(1);
                    resp[0] = pkt;

                    R2P2Response::new(resp, addr, port, req_id.clone())
                }
            }
        }, addr, port);

        server = Arc::new(RedisServer {
            server: r2p2,
            kv: OptiMap::with_capacity(512000),
        });

        server
    }
}

struct RedisKVEntry {
    pkt: Vec<CrossPacket>,
}

impl RedisKVEntry {
    fn new(req: R2P2Request) -> (String, Option<RedisKVEntry>) {
        let pkts = req.pkts();
        let payload = pkts[0].get_payload(0);
        let string = unsafe { from_utf8_unchecked(payload) };

        let split: Vec<&str> = string.split(' ').collect();

        // least we can have is GET "key"
        assert!(split.len() >= 2);

        let key = String::from(split[1]);

        match split[0] {
            "GET" => (key, None),
            "SET" => {
                let value = RedisKVEntry {
                    pkt: pkts.clone(),
                };

                (key, Some(value))
            },
            a => panic!("unknown request type: {}", a),
        }
    }
}

impl PartialEq for RedisKVEntry {
    fn eq(&self, other: &Self) -> bool {
        self.pkt[0].get_payload(0) == self.pkt[0].get_payload(0)
    }
}

impl Hash for RedisKVEntry {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.pkt[0].get_payload(0).hash(hasher);
    }
}
