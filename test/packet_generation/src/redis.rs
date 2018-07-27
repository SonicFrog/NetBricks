extern crate logmap;

use std::collections::hash_map::RandomState;
use std::marker::PhantomData;
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
      S: Scheduler + Sized,
{
    phantom_t: PhantomData<T>,
    phantom_s: PhantomData<S>,
}

impl<T, S> RedisServer<T, S>
where T: PacketTx + PacketRx + Clone + 'static,
      S: Sized + Scheduler + 'static,
{
    pub fn new(ports: Vec<T>,
               sched: &mut S,
               addr: Ipv4Addr,
               port: u16)
    {
        println!("settings up redis server {}:{}", addr, port);

        let kv: Arc<OptiMap<String, RedisKVEntry, RandomState>> =
            Arc::new(OptiMap::with_capacity(512000));

        let r2p2 = Arc::new(R2P2Server::new(ports, sched, box move |req| {
            let req_id = req.id().clone();
            let (key, entry) = RedisKVEntry::new(req);

            if let Some(e) = entry {
                let mut pkt = CrossPacket::new_from_raw();

                kv.put(key, e);
                pkt.add_data_head(4);

                {
                    let payload = pkt.get_mut_payload(0);

                    payload[0] = '"' as u8;
                    payload[1] = 'O' as u8;
                    payload[2] = 'K' as u8;
                    payload[3] = '"' as u8;
                }

                let mut resp = Vec::with_capacity(1);
                resp.push(pkt);

                R2P2Response::new(resp, req_id.clone())
            } else {
                if let Some(value) = kv.get(&key) {
                    R2P2Response::new(value.pkt.clone(), req_id.clone())
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

                    resp.push(pkt);

                    R2P2Response::new(resp, req_id.clone())
                }
            }
        }, addr, port));

        mem::forget(r2p2);
    }
}

struct RedisKVEntry {
    pkt: Vec<CrossPacket>,
}

impl RedisKVEntry {
    fn new(req: R2P2Request) -> (String, Option<RedisKVEntry>) {
        let mut pkts = req.pkts().clone();

        let tpe;
        let key;
        {
            let payload = pkts[0].get_payload(0);
            let string = unsafe { from_utf8_unchecked(payload) };
            let split: Vec<&str> = string.split("\r\n").collect();
            tpe = String::from(split[2]);
            key = String::from(split[4]);
        }

        match tpe.as_str() {
            "GET" | "get" => (key, None),
            "SET" | "set" => {
                let mut seen = 0;
                let mut off = 0;
                {
                    let payload = pkts[0].get_payload(0);
                    for i in 0..payload.len() {
                        let c = payload[i];

                        if c == ('\n' as u8) {
                            seen += 1;
                        }

                        if seen == 5 {
                            off = i + 1;
                        }
                    }
                }
                pkts[0].remove_data_head(off);

                let value = RedisKVEntry {
                    pkt: pkts.clone(),
                };

                (key, Some(value))
            },
            a => panic!("unknown request type: {}", a),
        }
    }
}
