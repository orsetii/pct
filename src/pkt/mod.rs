// This is the packet builder module for pct.
// It is the main interface that we run all operations through.

use crate::arp;
use crate::eth;
use crate::ipv4;
use crate::tcp;

pub fn build_eth(eth_frame: &eth::EthernetFrameSlice, flip: bool) -> [u8; 18] {
    let mut ret_pkt = [0u8; 18];
    if flip {
        // Note we alloc 4 bytes as preamble.

        // Store destination mac in buffer as we are
        // overwriting with old source address.
        // HARDCODED MAC
        let new_src_mac = [0xbe, 0xe9, 0x7d, 0x63, 0x31, 0xbc];
        let new_dest_mac: [u8; 6] = eth_frame.source();
        let proto = eth_frame.ethertype();

        ret_pkt[4..10].clone_from_slice(&new_dest_mac);
        ret_pkt[10..16].clone_from_slice(&new_src_mac);
        ret_pkt[16..18].clone_from_slice(&u16::to_be_bytes(proto));
    } else {
        // If no flip requested, we copy the first 18 bytes.
        // NOTE: the preamble will be assumed to be there.
        if eth_frame.slice[..4] == [0, 0, 0, 0] {
            ret_pkt.clone_from_slice(&eth_frame.slice[..18]);
        } else {
            // If not found, we prepend the null 4 bytes, and take the first 14
            // of the frame.
            println!("Couldnt find preamble in eth frame {:X?}", eth_frame.slice);
            ret_pkt[4..18].clone_from_slice(&eth_frame.slice[..14]);
        }
    }
    ret_pkt
}

pub fn build_ip(ip_frame: &ipv4::Ipv4PacketSlice, flip: bool) -> [u8; 20] {
    let mut ret_pkt = [0u8; 20];
    ret_pkt.clone_from_slice(&ip_frame.slice[..20]);
    //assert!(ipv4::calculate_checksum(ip_frame.slice) == 0);
    if flip {
        let new_src_ip = ip_frame.destination_ip();
        let new_dest_ip = ip_frame.source_ip();

        ret_pkt[10..12].clone_from_slice(&[0, 0]);
        ret_pkt[12..16].clone_from_slice(&u32::to_be_bytes(new_src_ip));
        ret_pkt[16..20].clone_from_slice(&u32::to_be_bytes(new_dest_ip));
        let csum = ipv4::calculate_checksum(&mut ret_pkt);
        ret_pkt[10..12].clone_from_slice(&u16::to_be_bytes(csum));
        ret_pkt
    } else {
        return ret_pkt;
    }
}

pub fn read_and_reply(
    buf: &mut [u8],
    buf_len: usize,
    table: &mut crate::arp::TranslationTable,
) -> (bool, usize) {
    let mut frame_buf = [0u8; 18];
    frame_buf.clone_from_slice(&buf[4..22]);
    let frame = eth::EthernetFrameSlice::read_from_slice(&frame_buf);
    let header = eth::EthernetHeader::from_header_slice(&frame);
    let proto = eth::EtherType::from_u16(header.ethertype);

    let mut buf_cnt = 0;
    match &proto {
        Some(x) => {
            if x == &eth::EtherType::Arp {
                assert!(buf_cnt == 0);
                let eth_reply_frame = build_eth(&frame, true);
                buf_cnt += 18;
                let arp_pkt = arp::read_packet(&buf[18..], &frame, table);
                if arp_pkt == None {
                    return (false, 0);
                } else {
                    let pkt_len = arp_pkt.unwrap().len();
                    buf[..buf_cnt].clone_from_slice(&eth_reply_frame);
                    buf[buf_cnt..buf_cnt + pkt_len].clone_from_slice(&arp_pkt.unwrap());
                    return (true, buf_cnt + pkt_len);
                }
            } else if x == &eth::EtherType::Ipv4 {
                match ipv4::read_packet(&buf[18..38]) {
                    Some(x) => {
                        assert!(buf_cnt == 0);

                        let eth_reply_frame = build_eth(&frame, true);
                        buf[..18].clone_from_slice(&eth_reply_frame);
                        buf_cnt += 18;

                        let mut ip_buf = [0u8; 20];
                        ip_buf.clone_from_slice(&buf[18..38]);
                        let ip_slice = ipv4::Ipv4PacketSlice { slice: &ip_buf };

                        let ip_reply_frame = build_ip(&ip_slice, true);
                        buf[buf_cnt..buf_cnt + ip_reply_frame.len()]
                            .clone_from_slice(&ip_reply_frame);
                        buf_cnt += ip_reply_frame.len();

                        use ipv4::ProtoType::*;
                        match x {
                            ICMP => {
                                println!("[ICMP] processing...");
                                let icmp_pkt = crate::icmp::read_packet(
                                    &frame,
                                    &ip_slice,
                                    &buf[buf_cnt..buf_cnt + buf_len],
                                );
                                if icmp_pkt == None {
                                    return (false, 0);
                                } else {
                                    let pkt_len = icmp_pkt.unwrap().len();
                                    buf[buf_cnt..buf_cnt + pkt_len]
                                        .clone_from_slice(&icmp_pkt.unwrap());
                                    buf_cnt += pkt_len;
                                    return (true, buf_cnt);
                                }
                            }
                            UDP => {
                                println!("[UDP] nop");
                                return (false, 0);
                            }
                            TCP => {
                                println!("[TCP] processing...");
                                let tcp_pkt = tcp::read_packet(
                                    &buf[buf_cnt..buf_cnt + buf_len],
                                    &ipv4::IPv4Packet::from_slice(ip_slice),
                                );
                                println!("LINE: {}", line!());
                                if tcp_pkt == None {
                                    return (false, 0);
                                } else {
                                    let pkt = tcp_pkt.unwrap();
                                    println!("buf cnt: {}", buf_cnt + pkt.1);
                                    buf[buf_cnt..buf_cnt + pkt.1].clone_from_slice(&pkt.0[..pkt.1]);
                                    return (true, buf_cnt + pkt.1);
                                }
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
