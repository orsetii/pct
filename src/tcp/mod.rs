use std::convert::TryInto;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHeaderFlags {
    /// robustness protection, not used much afaik, see RFC https://tools.ietf.org/html/rfc3540
    ns: bool,
    /// Congestion Window Reduced is used for informing that the sender reduced its sending rate.
    cwr: bool,
    /// ECN Echo is used for informing that the sender reduced its sending rate.
    ece: bool,
    /// Urgent Pointer indicates that the segment contains prioritized data.
    urg: bool,
    /// ACK field is used to communicate the state of the TCP handshake. It stays on for the remainder of the connection.
    ack: bool,
    /// PSH is used to indicate that the receiver should “push” the data to the application as soon as possible.
    psh: bool,
    /// RST resets the TCP connection.
    rst: bool,
    /// SYN is used to schronize sequence numbers in the intial handshake.
    syn: bool,
    /// FIN indicates the sender has finished sending data.
    fin: bool,
}

impl TcpHeaderFlags {
    /// Creates a new flag struct with all flags set to false.
    pub fn new() -> Self {
        TcpHeaderFlags {
            ns: false,
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
        }
    }

    pub fn to_u8(&self) -> [u8; 2] {
        let mut ret = [0u8; 2];
        if self.ns {
            ret[0] |= 0x01;
        }
        if self.cwr {
            ret[1] |= 0x80;
        }
        if self.ece {
            ret[1] |= 0x40;
        }
        if self.urg {
            ret[1] |= 0x20;
        }
        if self.ack {
            ret[1] |= 0x10;
        }
        if self.psh {
            ret[1] |= 0x08;
        }
        if self.rst {
            ret[1] |= 0x04;
        }
        if self.syn {
            ret[1] |= 0x02;
        }
        if self.fin {
            ret[1] |= 0x01;
        }
        ret
    }
}

///An TCP Header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHeader {
    /// The source port.
    src_port: u16,

    /// The destination port.
    dst_port: u16,

    /// Sequence Number represents the TCP segment’s window index.
    /// When handshaking, this contains the Initial Sequence Number (ISN).
    seq_number: u32,

    /// If the ACK flag is set then the value of this field is the next sequence number that the sender of the ACK is expecting.
    /// This acknowledges receipt of all prior bytes (if any).
    /// The first ACK sent by each end acknowledges the other end's initial sequence number itself, but no data
    ack_number: u32,

    /// NOTE: This is a 4-bit field, but we store this and the proceeding half in seperate 8 bit
    /// fields.
    data_offset: u8,

    /// Reserved should ALWAYS be set to zero. 3 bit field in actual packet structure.
    /// Kept to verify legitmeicy of packet wtf spelling
    reserved: u8,

    /// Flags is a 3 bit field used to control or identify fragments.
    /// bit 0: Reserved, must be zero.
    /// bit 1: Don't Fragment (DF)
    /// bit 2: More Fragments (MF)
    flags: TcpHeaderFlags,

    /// Window size is the size of the receive window, which specifies the number of window size
    /// units that the sender of this segment is currently willing to receive.
    /// Since this is a 16-bit field, the max is 65,535 bytes.
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
    options: [u8; 40],
}

impl TcpHeader {
    // TODO parse packet!!
    pub fn from_slice(slice: &TcpPacketSlice) -> Self {
        TcpHeader {
            src_port: slice.src_port(),
            dst_port: slice.dst_port(),
            seq_number: slice.seq_number(),
            ack_number: slice.ack_number(),
            data_offset: slice.data_offset(),
            reserved: slice.reserved(),
            flags: slice.flags(),
            window_size: slice.window_size(),
            checksum: slice.checksum(),
            urgent_pointer: slice.urgent_pointer(),
            options: slice.options(),
        }
    }
    pub fn to_slice(&self) -> [u8; 60] {
        let mut ret = [0u8; 60];
        ret[0..2].clone_from_slice(&u16::to_be_bytes(self.src_port));
        ret[2..4].clone_from_slice(&u16::to_be_bytes(self.dst_port));
        ret[4..8].clone_from_slice(&u32::to_be_bytes(self.seq_number));
        ret[8..12].clone_from_slice(&u32::to_be_bytes(self.ack_number));
        let flags_u8 = self.flags.to_u8();
        println!(
            "data offset pre: {} post: {}",
            self.data_offset,
            self.data_offset << 4
        );
        ret[12] = (0b10100000) | flags_u8[0];
        ret[13] = flags_u8[1];
        ret[14..16].clone_from_slice(&u16::to_be_bytes(self.window_size));
        // dumb implementatio, assume caller handles recalcuation, awkard here.
        ret[16..18].clone_from_slice(&u16::to_be_bytes(self.checksum));
        ret[18..20].clone_from_slice(&u16::to_be_bytes(self.urgent_pointer));
        ret[20..60].clone_from_slice(&self.options);
        ret
    }
    fn flip_sd(&mut self) {
        let new_dst = self.src_port;
        let new_src = self.dst_port;
        self.dst_port = new_dst;
        self.src_port = new_src;
    }
}

/// A slice containing an TCP Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpPacketSlice<'a> {
    pub slice: &'a [u8],
}

impl<'a> TcpPacketSlice<'a> {
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.slice[0], self.slice[1]])
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.slice[2], self.slice[3]])
    }

    pub fn seq_number(&self) -> u32 {
        u32::from_be_bytes([self.slice[4], self.slice[5], self.slice[6], self.slice[7]])
    }

    pub fn ack_number(&self) -> u32 {
        u32::from_be_bytes([self.slice[8], self.slice[9], self.slice[10], self.slice[11]])
    }

    pub fn data_offset(&self) -> u8 {
        // number is a 4 byte field.
        let mut ret = self.slice[12] & 0xf0;
        ret >>= 4;
        ret *= 4;
        assert!(ret >= 20 && ret <= 60);
        ret
    }

    pub fn reserved(&self) -> u8 {
        self.slice[12] & 0x07
    }

    pub fn flags(&self) -> TcpHeaderFlags {
        let mut flags = TcpHeaderFlags::new();

        if self.slice[12] & 0x01 != 0 {
            flags.ns = true;
        }

        if self.slice[13] & 0x80 != 0 {
            flags.cwr = true;
        }
        if self.slice[13] & 0x40 != 0 {
            flags.ece = true;
        }
        if self.slice[13] & 0x20 != 0 {
            flags.urg = true;
        }
        if self.slice[13] & 0x10 != 0 {
            flags.ack = true;
        }
        if self.slice[13] & 0x08 != 0 {
            flags.psh = true;
        }
        if self.slice[13] & 0x04 != 0 {
            flags.rst = true;
        }
        if self.slice[13] & 0x02 != 0 {
            flags.syn = true;
        }
        if self.slice[13] & 0x01 != 0 {
            flags.fin = true;
        }

        println!("Flags Found: {:?}", flags);
        flags
    }

    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes([self.slice[14], self.slice[15]])
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.slice[16], self.slice[17]])
    }

    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes([self.slice[18], self.slice[19]])
    }

    /// note that extra 0 fields are added, ALWAYS up to the 40 byte maximum.
    /// We can len check the actual data via the data offset field
    pub fn options(&self) -> [u8; 40] {
        let data_max = self.data_offset() as usize - 20;
        println!("data max: {}", data_max);
        let mut ret = [0u8; 40];
        println!(
            "selfslicelen: {} - ret len: {}",
            &self.slice[20..data_max + 20].len(),
            ret[..data_max].len(),
        );
        ret[..data_max].clone_from_slice(&self.slice[20..data_max + 20]);
        println!("Options extracted: {:X?}", ret);
        ret
    }

    pub fn read_from_slice(data: &'a [u8; 352]) -> Self {
        TcpPacketSlice { slice: data }
    }
}

fn tcp_checksum(tcp_packet: &TcpPacketSlice, ipv4_packet: &crate::ipv4::IPv4Packet) -> u16 {
    let data = tcp_packet.slice;
    // Create new data slice with psuedo ip header attached.
    let mut psuedo_header = [0u8; 12];
    psuedo_header[0..4].clone_from_slice(&u32::to_be_bytes(ipv4_packet.source_ip));
    psuedo_header[4..8].clone_from_slice(&u32::to_be_bytes(ipv4_packet.dest_ip));
    psuedo_header[8..10].clone_from_slice(&u16::to_be_bytes(ipv4_packet.total_len));
    psuedo_header[10] = crate::ipv4::ProtoType::to_u8(&ipv4_packet.protocol);
    crate::ipv4::checksum(&[&psuedo_header, data].concat())
}

/// returns a TCP Packet depending on what was contained in recv'd TCP packet.
/// We use a 1500 size max array size as this is the MTU for ethernet.
pub fn read_packet(
    data: &[u8],
    ipv4_packet: &crate::ipv4::IPv4Packet,
) -> Option<([u8; 1500], usize)> {
    // assuming that data means TCP and above layer.
    let tcp_slice = TcpPacketSlice { slice: data };

    let mut tcp_packet = TcpHeader::from_slice(&tcp_slice);

    // check the checksum
    //let original_csum_res = tcp_checksum(&tcp_slice, ipv4_packet);
    println!("Recvd TCP Packet: {:?}", tcp_packet);
    let mut buf = [0u8; 1500];

    if tcp_packet.flags.syn {
        tcp_packet.flags.ack = true;
        tcp_packet.flip_sd();
        tcp_packet.data_offset = 40;

        let old_ack = tcp_packet.ack_number;
        let old_seq = tcp_packet.seq_number;
        tcp_packet.ack_number = tcp_packet.seq_number + 1;
        println!("FOUND ACK: {} : FOUND SEQ: {}", old_ack, old_seq);
        if old_ack == 0 {
            // if ack is zero, set an ISN.
            tcp_packet.seq_number = 300;
        } else {
            tcp_packet.seq_number = old_ack + 1;
        }
        tcp_packet.checksum = 0;
        let tcp_outbuf = tcp_packet.to_slice();
        let csum = tcp_checksum(
            &TcpPacketSlice {
                slice: &tcp_outbuf[..(tcp_packet.data_offset as usize)],
            },
            ipv4_packet,
        );
        println!("CHECKSUM: {:X?}", csum);
        tcp_packet.checksum = csum;
        let tcp_outbuf = tcp_packet.to_slice();
        println!(
            "TCP PACKET STRUCT: {:?}\nTCP BUF: {:X?}",
            tcp_packet, tcp_outbuf
        );
        buf[..tcp_packet.data_offset as usize]
            .clone_from_slice(&tcp_outbuf[..tcp_packet.data_offset as usize]);
    }
    Some((buf, tcp_packet.data_offset as usize))
}
