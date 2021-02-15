// struct icmp_v4 {
// uint8_t type;
// uint8_t code;
// uint16_t csum;
// uint8_t data[];
//}
//

use crate::eth;
use std::convert::TryInto;
#[derive(Clone, Debug, Eq, PartialEq)]
enum IcmpType {
    Reply = 0x00,
    DstUnreachable = 0x03,
    SrcQuench = 0x04,
    Redirect = 0x05,
    Echo = 0x08,
    RouterAdv = 0x09,
    RouterSol = 0x0a,
    Timeout = 0x0b,
    Malformed = 0x0c,
    Error = 0xff,
}

impl IcmpType {
    pub fn from_u8(value: u8) -> Option<IcmpType> {
        use self::IcmpType::*;
        match value {
            0x00 => Some(Reply),
            0x03 => Some(DstUnreachable),
            0x04 => Some(SrcQuench),
            0x05 => Some(Redirect),
            0x08 => Some(Echo),
            0x09 => Some(RouterAdv),
            0x0a => Some(RouterSol),
            0x0b => Some(Timeout),
            0x0c => Some(Malformed),
            _ => {
                println!("Couldn't find protcol for 0x{:02x}", value);
                None
            }
        }
    }
}

///An ICMP Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcmpPacket {
    /// msg_type defines the 'type', or purpose of the packet.
    msg_type: IcmpType,

    /// code defines the subtype of the packet.
    code: u8,

    /// checksum of the packet, to use the calculate_checksum function on.
    checksum: u16,

    /// rest of header is used as a vague field as this can contain
    /// various different data depending on packet type & subtype
    rest_of_header: [u8; 4],

    /// same for rest_of_packet
    _rest_of_packet: &'static [u8],
}

impl IcmpPacket {
    pub fn from_slice(slice: &IcmpPacketSlice) -> Self {
        IcmpPacket {
            msg_type: slice.msg_type(),
            code: slice.code(),
            checksum: slice.checksum(),
            rest_of_header: slice.rest_of_header(),
            _rest_of_packet: &[0u8; 0],
        }
    }
}

///A slice containing an ARP Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcmpPacketSlice<'a> {
    slice: &'a [u8],
}

impl<'a> IcmpPacketSlice<'a> {
    fn msg_type(&self) -> IcmpType {
        IcmpType::from_u8(self.slice[0]).unwrap_or(IcmpType::Error)
    }

    fn code(&self) -> u8 {
        self.slice[1]
    }

    fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.slice[2], self.slice[3]])
    }

    /// This is abstract as the format can differ depending on what type of the ICMP packet.
    fn rest_of_header(&self) -> [u8; 4] {
        self.slice[4..8]
            .try_into()
            .expect("couldn't convert data slice into array")
    }

    fn rest_of_packet(&self, len: usize) -> &[u8] {
        &self.slice[8..len]
    }

    pub fn read_from_slice(data: &'a [u8]) -> Self {
        IcmpPacketSlice { slice: data }
    }
}

pub fn read_packet(
    etherframe: &eth::EthernetFrameSlice,
    ipframe: &crate::ipv4::Ipv4PacketSlice,
    icmpframe: &[u8],
    nic: &tun_tap::Iface,
) -> Result<(), Box<dyn std::error::Error>> {
    let packet_slice = &IcmpPacketSlice { slice: &icmpframe };
    let icmp_data = IcmpPacket::from_slice(packet_slice);

    match icmp_data.msg_type {
        IcmpType::Reply => {
            println!(
                "Ping Reply from {}",
                std::net::Ipv4Addr::from(ipframe.destination_ip())
            );
        }
        IcmpType::Echo => {
            // If we have a request, reply!
            let total_buf_size: usize = 18 + ipframe.slice.len() + icmpframe.len();
            let mut buf = [0u8; 1600];
            let new_dest_mac: [u8; 6] = etherframe.source();

            buf[4..10].clone_from_slice(&new_dest_mac);
            buf[10..16].clone_from_slice(&crate::eth::MAC);
            buf[16..18].clone_from_slice(&etherframe.slice[12..14]);
            // Ethernet Frame Done

            buf[18..38].clone_from_slice(ipframe.slice);

            let new_dest_ip = &ipframe.slice[12..16];
            let new_src_ip = &ipframe.slice[16..20];
            buf[30..34].clone_from_slice(&new_src_ip);
            buf[34..38].clone_from_slice(&new_dest_ip);
            // NOTE: Don't need to recalculate anything since we don't change any IPv4 Data..
            buf[38..38 + icmpframe.len()].clone_from_slice(icmpframe);

            // This fucking works?? So WHY does, when I change values it can't compute the correct
            // checksum... AHH
            if crate::ipv4::checksum(&buf[38..(38 + 16 + 48)]) != 0 {
                println!("----------------------------\nCHECKSUM INVALID!!!\n----------------------------\n");
                return Ok(());
            }
            buf[38] = 0;
            buf[40] = 0;
            buf[41] = 0;
            let icmp_csum = crate::ipv4::checksum(&buf[38..(38 + 16 + 48)]);
            buf[40] = icmp_csum as u8;
            buf[41] = (icmp_csum >> 8) as u8;

            let sent_len = nic.send(&buf[..total_buf_size]);

            println!(
                "Sent ICMP reply of size: {0:?} for IP: {1:X?}",
                sent_len.unwrap(),
                &new_dest_ip,
            );
        }

        _ => {
            println!("Unsure how to process type: {:?}", icmp_data.msg_type);
        }
    }
    Ok(())
}
