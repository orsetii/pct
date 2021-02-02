use tun_tap::Iface;

///Ether type enum present in ethernet II header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtoType {
    ICMP = 0x01,
    TCP = 0x06,
    UDP = 0x17,
}

impl ProtoType {
    pub fn from_u8(value: u8) -> Option<ProtoType> {
        use self::ProtoType::*;
        match value {
            0x01 => Some(ICMP),
            0x06 => Some(TCP),
            0x11 => Some(UDP),
            _ => {
                println!("Couldn't find protcol for 0x{:02x}", value);
                None
            }
        }
    }
}

///An Ipv4 Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IPv4Packet {
    /// version indicates the version of the IP. For our case and IPv4, this should always be 4.
    version: u8,

    /// ihl is the internet header length. This contains the entire size, and if this is more than
    /// 5, options is a field in the packet. I am not parsing options however.
    ihl: u8,

    /// DSCP is unused but here for if we want to add in the future. It is a 6 byte field.
    dscp: u8,

    /// ECN is the Explicit Congestion Notification. Not used at the moment.
    ecn: u8,

    /// Total Length is a 16 byte number defining the entire packet size in bytes.
    total_len: u16,

    /// identification is used for identifying a group of fragments of a single datagram, not
    /// used at the moment.
    identification: u16,

    /// Flags is a 3 bit field used to control or identify fragments.
    /// bit 0: Reserved, must be zero.
    /// bit 1: Don't Fragment (DF)
    /// bit 2: More Fragments (MF)
    flags: u8,

    /// Fragment offset is measured in eight-byte blocks, this is pretty much always 0
    /// and not being used at the moment also.
    fragment_offset: u16,

    /// Time to Live helps to prevent datagrams from floating around and persisting
    /// as this field limits its lifetimes.
    ///
    /// In practice this field has become a hop count, where each time the datagram arrives
    /// at a router, the router decrements the TTL field by one. When the TTL field hits
    /// zero the router discards the packet and sends an ICMP Time Exceeded message to the sender.
    /// traceroute uses these ICMP Time Exceeded messages to print the routers used by packets to
    /// go from the source to the desitnation.
    ttl: u8,

    /// protocol defines the protocol used in the data portion of the IP datagram.
    protocol: u8,

    /// header_checksum defines the error checking mechanism of IPv4 Packets.
    /// It is a 16 bit field.
    ///
    /// When a packet arrives at a router, the router decreases the TTL field, so the router
    /// must calculate a new checksum.
    header_checksum: u16,

    pub source_ip: u32,

    pub dest_ip: u32,
}

impl IPv4Packet {
    pub fn from_slice(slice: &Ipv4PacketSlice) -> Self {
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
            // TODO make a function that checks the checksum,
            // and one that creates a new one after decrementing the
            // TTL field.
            header_checksum: slice.header_checksum(),
            source_ip: slice.source_ip(),
            dest_ip: slice.destination_ip(),
        }
    }
}

///A slice containing an ARP Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4PacketSlice<'a> {
    pub slice: &'a [u8],
}

impl<'a> Ipv4PacketSlice<'a> {
    /// Grabs the first half of the first byte of the IPv4 Header.
    fn version(&self) -> u8 {
        return 0xF0 & self.slice[0];
    }

    /// Grabs the second half of the first byte of the IPv4 Header.
    fn ihl(&self) -> u8 {
        0x0F & self.slice[0]
    }

    /// Grabs the first six bits of the second byte of the IPv4 Header.
    fn dscp(&self) -> u8 {
        0x2F & self.slice[1]
    }

    /// Grabs the last two bits of the second byte of the IPv4 Header.
    fn ecn(&self) -> u8 {
        0x0C & self.slice[1]
    }

    fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.slice[2], self.slice[3]])
    }

    fn identification(&self) -> u16 {
        u16::from_be_bytes([self.slice[4], self.slice[5]])
    }

    /// Grabs the first three bits of the second byte of the IPv4 Header.
    fn flags(&self) -> u8 {
        0x70 & self.slice[6]
    }

    /// Grabs the last 12 bits of the second byte of the IPv4 Header.
    fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([(0x8F & self.slice[6]), self.slice[7]])
    }

    fn ttl(&self) -> u8 {
        self.slice[8]
    }

    fn protocol(&self) -> u8 {
        self.slice[9]
    }

    fn header_checksum(&self) -> u16 {
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
}

// The checksum field is the 16 bit one’s complement of the one’s complement sum of all
// 16 bit words in the header.
// For purposes of computing the checksum, the value of the checksum field is zero.
// compute checksum for 'count' bytes.

fn parse_checksum(hdr: &Ipv4PacketSlice) -> u16 {
    let mut sum: u32 = 0;

    let mut i: usize = 0;

    let mut count: usize = 20;
    while count > 1 {
        // Inner Loop
        sum += u32::from_be_bytes([hdr.slice[i], hdr.slice[i + 1], 0, 0]);
        count -= 2;
        i += 1;
    }

    // Add leftover byte if any.
    if count > 0 {
        sum += u32::from_be_bytes([hdr.slice[i], 0, 0, 0]);
    }

    sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);

    let result = ((sum & 0xffff) + (sum >> 16)) as u16;
    !result
}

pub fn read_packet(data: &[u8]) -> Option<ProtoType> {
    let mut packet_slice = Ipv4PacketSlice { slice: data };

    let packet = IPv4Packet::from_slice(&packet_slice);

    let checksum = parse_checksum(&packet_slice);
    println!("Returned Checksum: {:x?}", checksum);

    let check_arr = u16::to_be_bytes(checksum);

    self::ProtoType::from_u8(packet.protocol)
}
