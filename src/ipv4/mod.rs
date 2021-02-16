use std::collections::HashMap;
use std::convert::TryInto;
use tun_tap::Iface;

/// what protocol?
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtoType {
    ICMP = 0x01,
    IGMP = 0x02,
    TCP = 0x06,
    UDP = 0x17,
}

impl ProtoType {
    pub fn from_u8(value: u8) -> Option<ProtoType> {
        use self::ProtoType::*;
        match value {
            0x01 => Some(ICMP),
            0x02 => Some(IGMP),
            0x06 => Some(TCP),
            0x11 => Some(UDP),
            _ => {
                println!("Couldn't find protcol for 0x{:02x}", value);
                None
            }
        }
    }

    pub fn to_u8(value: &Option<ProtoType>) -> u8 {
        use self::ProtoType::*;
        match value {
            Some(ICMP) => 0x01,
            Some(IGMP) => 0x02,
            Some(TCP) => 0x06,
            Some(UDP) => 0x11,
            None => {
                println!("No Protocol number found!");
                0
            }
        }
    }
}

///An Ipv4 Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IPv4Packet {
    /// version indicates the version of the IP. For our case and IPv4, this should always be 4.
    pub version: u8,

    /// ihl is the internet header length. This contains the entire size, and if this is more than
    /// 5, options is a field in the packet. I am not parsing options however.
    pub ihl: u8,

    /// DSCP is unused but here for if we want to add in the future. It is a 6 byte field.
    pub dscp: u8,

    /// ECN is the Explicit Congestion Notification. Not used at the moment.
    pub ecn: u8,

    /// Total Length is a 16 byte number defining the entire packet size in bytes.
    pub total_len: u16,

    /// identification is used for identifying a group of fragments of a single datagram, not
    /// used at the moment.
    pub identification: u16,

    /// Flags is a 3 bit field used to control or identify fragments.
    /// bit 0: Reserved, must be zero.
    /// bit 1: Don't Fragment (DF)
    /// bit 2: More Fragments (MF)
    pub flags: u8,

    /// Fragment offset is measured in eight-byte blocks, this is pretty much always 0
    /// and not being used at the moment also.
    pub fragment_offset: u16,

    /// Time to Live helps to prevent datagrams from floating around and persisting
    /// as this field limits its lifetimes.
    ///
    /// In practice this field has become a hop count, where each time the datagram arrives
    /// at a router, the router decrements the TTL field by one. When the TTL field hits
    /// zero the router discards the packet and sends an ICMP Time Exceeded message to the sender.
    /// traceroute uses these ICMP Time Exceeded messages to print the routers used by packets to
    /// go from the source to the desitnation.
    pub ttl: u8,

    /// protocol defines the protocol used in the data portion of the IP datagram.
    pub protocol: Option<ProtoType>,

    /// header_checksum defines the error checking mechanism of IPv4 Packets.
    /// It is a 16 bit field.
    ///
    /// When a packet arrives at a router, the router decreases the TTL field, so the router
    /// must calculate a new checksum.
    // TODO not sure when to calculate, ig check per proto?
    pub header_checksum: u16,

    pub source_ip: u32,

    pub dest_ip: u32,

    /// options is an optional field verifying some things.
    pub _options: [u8; 12],
}

impl IPv4Packet {
    // TODO parse packet!!
    pub fn from_slice(slice: Ipv4PacketSlice) -> Self {
        IPv4Packet {
            version: slice.version(),
            ihl: slice.ihl(),
            dscp: slice.dscp(),
            ecn: slice.ecn(),
            total_len: slice.total_len(),
            identification: slice.identification(),
            flags: slice.flags(),
            fragment_offset: slice.fragment_offset(),
            ttl: slice.ttl(),
            protocol: slice.protocol(),
            header_checksum: slice.header_checksum(),
            source_ip: slice.source_ip(),
            dest_ip: slice.destination_ip(),
            // keeping this is a blank field, dont plan on using
            // atm, but for future.
            _options: [0u8; 12],
        }
    }
}

/// A slice containing an ARP Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4PacketSlice<'a> {
    pub slice: &'a [u8],
}

impl<'a> Ipv4PacketSlice<'a> {
    /// Grabs the first half of the first byte of the IPv4 Header.
    pub fn version(&self) -> u8 {
        return 0xF0 & self.slice[0];
    }

    /// Grabs the second half of the first byte of the IPv4 Header.
    pub fn ihl(&self) -> u8 {
        0x0F & self.slice[0]
    }

    /// Grabs the first six bits of the second byte of the IPv4 Header.
    pub fn dscp(&self) -> u8 {
        0x2F & self.slice[1]
    }

    /// Grabs the last two bits of the second byte of the IPv4 Header.
    pub fn ecn(&self) -> u8 {
        0x0C & self.slice[1]
    }

    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.slice[2], self.slice[3]])
    }

    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.slice[4], self.slice[5]])
    }

    /// Grabs the first three bits of the second byte of the IPv4 Header.
    pub fn flags(&self) -> u8 {
        0x70 & self.slice[6]
    }

    /// Grabs the last 12 bits of the second byte of the IPv4 Header.
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([(0x8F & self.slice[6]), self.slice[7]])
    }

    pub fn ttl(&self) -> u8 {
        self.slice[8]
    }

    pub fn protocol(&self) -> Option<ProtoType> {
        ProtoType::from_u8(self.slice[9])
    }

    pub fn header_checksum(&self) -> u16 {
        u16::from_be_bytes([self.slice[10], self.slice[11]])
    }

    pub fn source_ip(&self) -> u32 {
        u32::from_be_bytes([
            self.slice[12],
            self.slice[13],
            self.slice[14],
            self.slice[15],
        ])
    }
    pub fn destination_ip(&self) -> u32 {
        u32::from_be_bytes([
            self.slice[16],
            self.slice[17],
            self.slice[18],
            self.slice[19],
        ])
    }

    pub fn read_from_slice(data: &'a [u8; 28]) -> Self {
        Ipv4PacketSlice { slice: data }
    }
}

/// ipv4 checksum
pub fn calculate_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = header.len();

    while i > 1 {
        sum += u16::from_be_bytes([header[i - 2], header[i - 1]]) as u32;
        i -= 2;
    }

    if i == 1 {
        sum += header[i - 1] as u32;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    !sum as u16
}

/// icmp checksum
pub fn checksum(slice: &[u8]) -> u16 {
    let (head, slice, tail) = unsafe { slice.align_to::<u16>() };
    if !head.is_empty() || !tail.is_empty() {
        panic!("checksum() input should be 16-bit aligned");
    }

    fn add(a: u16, b: u16) -> u16 {
        let s: u32 = (a as u32) + (b as u32);
        if s & 0x1_00_00 > 0 {
            // overflow, add carry bit
            (s + 1) as u16
        } else {
            s as u16
        }
    }

    !slice.iter().fold(0, |x, y| add(x, *y))
}

#[cfg(test)]
#[test]
fn test_checksum() {
    let ret = calculate_checksum(&[
        0x45, 0x00, 0x00, 0x54, 0x41, 0xe0, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00,
        0x04, 0x0a, 0x00, 0x00, 0x05,
    ]);

    assert_eq!(ret, 0xe4c0);

    let next = &[
        0x45, 0x00, 0x00, 0x54, 0x41, 0xe0, 0x40, 0x00, 0x40, 0x01, 0xe4, 0xc0, 0x0a, 0x00, 0x00,
        0x04, 0x0a, 0x00, 0x00, 0x05,
    ];

    assert_eq!(calculate_checksum(next), 0);
}

/// returns the protocol it detects.
pub fn read_packet(data: &[u8]) -> Option<ProtoType> {
    // NOTE: assuming that 'data' contains ipv4 data and 'above'
    let slice =
        Ipv4PacketSlice::read_from_slice(data[..28].try_into().expect("Couldnt convert ipv4 data"));

    let ip_data = IPv4Packet::from_slice(slice);

    ip_data.protocol
}
