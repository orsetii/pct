#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHeaderFlags {
    ns: bool,
    cwr: bool,
    ece: bool,
    urg: bool,
    ack: bool,
    psh: bool,
    syn: bool,
    fin: bool,
}

///An TCP Header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHeader {
    /// The source port.
    src_port: u16,

    /// The destination port.
    dest_port: u16,

    /// Sequence Number represents the TCP segment’s window index.
    /// When handshaking, this contains the Initial Sequence Number (ISN).
    seq_number: u32,

    /// If the ACK flag is set then the value of this field is the next sequence number that the sender of the ACK is expecting.
    /// This acknowledges receipt of all prior bytes (if any).
    /// The first ACK sent by each end acknowledges the other end's initial sequence number itself, but no data.
    ack_number: u32,

    /// Total Length is a 16 byte number defining the entire packet size in bytes.
    total_len: u16,

    /// NOTE: This is a 4-bit field, but we store this and the proceeding half in seperate 8 bit
    /// fields.
    header_len: u8,

    /// Reserved should ALWAYS be set to zero. 3 bit field in actual packet structure.
    reserved: u8,

    /// Flags is a 3 bit field used to control or identify fragments.
    /// bit 0: Reserved, must be zero.
    /// bit 1: Don't Fragment (DF)
    /// bit 2: More Fragments (MF)
    flags: u8,

    /// Window size is the size of the receive window, which specifies the number of window size
    /// units that the sender of this segment is currently willing to receive.
    window_size: u16,

    /// The 16-bit checksum field is used for error-checking of the TCP header,
    /// the payload and an IP pseudo-header.
    ///
    /// The pseudo-header consists of the source IP address, the destination IP address, the protocol number
    /// for the TCP protocol (6) and the length of the TCP headers and payload (in bytes).
    checksum: u16,

    /// If the URG flag is set, then this 16-bit field is an offset from the sequence number
    /// indicating the last urgent data byte.
    urgent_pointer: u16,

    /// options is an optional field with a variable size of 0-320 bits(0-40 bytes),  in 32-bit units.
    /// The length is determined by the header_len field.
    _options: [u8; 40],
}

impl TcpHeader {
    // TODO parse packet!!
    pub fn from_slice(slice: TcpPacketSlice) -> Self {
        TcpHeader {}
    }
}

/// A slice containing an ARP Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpPacketSlice<'a> {
    pub slice: &'a [u8],
}

impl<'a> TcpPacketSlice<'a> {
    pub fn read_from_slice(data: &'a [u8; 28]) -> Self {
        TcpPacketSlice { slice: data }
    }
}
