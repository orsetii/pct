// This is the packet builder module for pct.
// It is the main interface that we run all operations through.

use crate::arp;
use crate::eth;
use crate::ipv4;
use crate::tcp;

pub fn read_and_reply(
    buf: &mut [u8],
    buf_len: usize,
    table: &mut crate::arp::TranslationTable,
) -> (bool, usize) {
    let frame = eth::EthernetFrameSlice::read_from_slice(&buf[4..]);
    let header = eth::EthernetHeader::from_header_slice(&frame);
    let proto = eth::EtherType::from_u16(header.ethertype);
    let payload = &frame.slice[14..];
    let ip_slice = ipv4::Ipv4PacketSlice {
        slice: &payload[..20],
    };

    match &proto {
        Some(x) => {
            if x == &eth::EtherType::Arp {
                let arp_pkt = arp::read_packet(&payload, &frame, table);
                if arp_pkt == None {
                    return (false, 0);
                } else {
                    let pkt_len = arp_pkt.unwrap().len();
                    buf[..pkt_len].clone_from_slice(&arp_pkt.unwrap());
                    return (true, pkt_len);
                }
            } else if x == &eth::EtherType::Ipv4 {
                match ipv4::read_packet(&payload) {
                    Some(x) => {
                        // TODO if UDP, print error and move on.
                        use ipv4::ProtoType::*;
                        match x {
                            ICMP => {
                                println!("[ICMP] processing...");
                                let icmp_pkt = crate::icmp::read_packet(
                                    &frame,
                                    &ip_slice,
                                    &payload[20..buf_len],
                                );
                                if icmp_pkt == None {
                                    return (false, 0);
                                } else {
                                    let pkt_len = icmp_pkt.unwrap().len();
                                    buf[..pkt_len].clone_from_slice(&icmp_pkt.unwrap());
                                    return (true, pkt_len);
                                }
                            }
                            UDP => {
                                println!("[UDP] nop");
                            }
                            TCP => {
                                println!("[TCP] processing...");
                                let tcp_pkt = tcp::read_packet(
                                    &payload[20..buf_len],
                                    &ipv4::IPv4Packet::from_slice(ip_slice),
                                );
                                //let pkt_len = tcp_pkt.unwrap().len();
                                //buf[..pkt_len].clone_from_slice(&tcp_pkt.unwrap());
                                // TODO fix this once packet replying is done and shit
                                return (false, 0);
                            }
                            IGMP => {
                                println!("[IGMP] nop");
                            }
                        }
                    }
                    None => {}
                }
            }
        }

        None => {
            println!("Bad Protocol. Received Packets: 0x{:X?}", header.ethertype);
        }
    }
    return (false, 0);
}
