use std::convert::TryInto;
use tun_tap::Iface;

///Ether type enum present in ethernet II header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    VlanTaggedFrame = 0x8100,
    ProviderBridging = 0x88A8,
    VlanDoubleTaggedFrame = 0x9100,
}

impl EtherType {
    ///Tries to convert a raw ether type value to the enum. Returns None if the value does not exist in the enum.
    pub fn from_u16(value: u16) -> Option<EtherType> {
        use self::EtherType::*;
        match value {
            0x0800 => Some(Ipv4),
            0x86dd => Some(Ipv6),
            0x0806 => Some(Arp),
            0x0842 => Some(WakeOnLan),
            0x88A8 => Some(ProviderBridging),
            0x8100 => Some(VlanTaggedFrame),
            0x9100 => Some(VlanDoubleTaggedFrame),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthernetHeader {
    /// dmac is the destination MAC address.
    pub destination_mac: [u8; 6],

    /// smac is the source MAC address.
    pub source_mac: [u8; 6],

    /// Ethertype is a two-octect (2 byte) field, used to indicate the protocol is in the payload
    /// of the frame and how the layer 2 of the receviing end should process it.
    pub ethertype: u16,
    // The Frame Check Sequence is a 4-byte CRC that allows deteection of corrupted data within
    // the entire frame as it is received on the receiver side.
    // We can compute this with a similar algo to this: https://stackoverflow.com/questions/9286631/ethernet-crc32-calculation-software-vs-algorithmic-result
    // TODO implement this, we will skip checking this field for now.
    //frame_check_sequence: u32,
}

impl EthernetHeader {
    pub fn from_header_slice(slice: &EthernetFrameSlice) -> Self {
        EthernetHeader {
            destination_mac: slice.destination(),
            source_mac: slice.source(),
            ethertype: slice.ethertype(),
        }
    }
}

///A slice containing an ethernet 2 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthernetFrameSlice<'a> {
    pub slice: &'a [u8],
}

impl<'a> EthernetFrameSlice<'a> {
    /// Using functions to grab this data so we can add to implementations and error/bounds
    /// checking easier.
    pub fn destination(&self) -> [u8; 6] {
        self.slice[..6]
            .try_into()
            .expect("Error in source MAC tcp.rs/mod.rs:74")
    }

    pub fn source(&self) -> [u8; 6] {
        self.slice[6..12]
            .try_into()
            .expect("Error in source MAC tcp.rs/mod.rs:74")
    }

    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes([self.slice[12], self.slice[13]])
    }

    pub fn read_from_slice(data: &'a [u8]) -> Self {
        EthernetFrameSlice { slice: data }
    }

    pub fn payload(&self, _data_len: usize) -> [u8; 1522] {
        self.slice[16..1506]
            .try_into()
            .expect("Couldnt convert payload into array.")
    }
}

pub fn nic_init(table: &mut crate::arp::TranslationTable) {
    table.insert(
        u32::from_be_bytes([0x0a, 0x0, 0x0, 0x02]),
        [0xbe, 0xe9, 0x7d, 0x63, 0x31, 0xbc],
    );
    table.insert(
        u32::from_be_bytes([0x0a, 0x0, 0x0, 0x04]),
        [0xbe, 0xe9, 0x7d, 0x63, 0x31, 0xbc],
    );

    table.insert(
        u32::from_be_bytes([0x7f, 0x0, 0x0, 0x01]),
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
}

pub mod icmp {

    pub struct Icmp4Packet {
        packet_type: u8,

        code: u8,

        checksum: u16,
    }

    impl Icmp4Packet {
        pub fn from_slice(slice: &Icmp4PacketSlice) -> Self {
            Icmp4Packet {
                packet_type: slice.packet_type(),
                code: slice.code(),
                checksum: slice.checksum(),
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Icmp4PacketSlice<'a> {
        slice: &'a [u8],
    }

    impl<'a> Icmp4PacketSlice<'a> {
        fn packet_type(&self) -> u8 {
            self.slice[0]
        }

        fn code(&self) -> u8 {
            self.slice[1]
        }

        fn checksum(&self) -> u16 {
            u16::from_be_bytes([self.slice[2], self.slice[3]])
        }
    }

    pub fn read_packet(
        eth_hdr: &crate::tcp::EthernetFrameSlice,
        ip_hdr: &crate::ipv4::Ipv4PacketSlice,
        data: &[u8],
        nic: &tun_tap::Iface,
    ) {
        let packet_buf = Icmp4PacketSlice { slice: data };

        let packet = Icmp4Packet::from_slice(&packet_buf);

        println!("Received Packet: {:X?}", packet_buf);

        match packet.packet_type {
            0x0 => {
                // If we have a reply, print that.
                println!(
                    "Ping Reply from {}",
                    std::net::Ipv4Addr::from(ip_hdr.destination_ip())
                );
            }
            0x8 => {
                // If we have a request, reply!
                let total_buf_size: usize = 18 + ip_hdr.slice.len() + data.len();
                let mut buf = [0u8; 1600];
                let new_src_mac = [0xbe, 0xe9, 0x7d, 0x63, 0x31, 0xbc];
                let new_dest_mac: [u8; 6] = eth_hdr.source();

                buf[4..10].clone_from_slice(&new_dest_mac);
                println!("{}", line!());
                buf[10..16].clone_from_slice(&new_src_mac);
                println!("{}", line!());
                buf[16..18].clone_from_slice(&eth_hdr.slice[12..14]);
                println!("{}", line!());
                buf[18..38].clone_from_slice(ip_hdr.slice);
                println!("{}", line!());

                let new_src_ip = &ip_hdr.slice[12..16];
                let new_dest_ip = &ip_hdr.slice[16..20];
                buf[30..34].clone_from_slice(&new_src_ip);
                buf[34..38].clone_from_slice(&new_dest_ip);

                buf[ip_hdr.slice.len()..(ip_hdr.slice.len() + data.len())].clone_from_slice(data);

                let sent_len = nic.send(&buf[..total_buf_size]);

                println!(
                    "Sent ICMP reply of size: {0:?} for IP: {1:X?}",
                    sent_len.unwrap(),
                    &new_dest_ip,
                );
                println!("Sent: {:X?}", &buf[..total_buf_size]);
            }
            _ => {
                println!("Couldn't Parse ICMP opcode");
            }
        }
    }
}
