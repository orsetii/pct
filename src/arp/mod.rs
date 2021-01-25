pub struct ArpHeader {
    /// hardware_type describes what link layer type is used
    /// In our case this will be ethernet - 0x0001
    hardware_type: u16,

    /// hardware_size indicates the size of the hardware field.
    hardware_size: u8,

    /// proto_type indicates the Protocol Type. In our case this
    /// will be IPv4, which is 0x0800
    proto_type: u16,

    /// proto_size indicates the size of the Protocol field.
    proto_size: u8,

    /// opcode declares the type of the ARP message. It can be
    /// an ARP request (1), ARP reply (2), RARP request (3)
    /// or RARP reply (4).
    opcode: u16,

    /// data contains the actual payload of the ARP message, in our case, this will contain IPv4
    /// specific information.
    data: [u8],
}

pub struct arp_ipv4 {
    /// Source's MAC Address.
    source_mac: [u8; 6],

    /// Source's IP Address
    source_ip: u32,

    /// Destination's MAC Address
    destination_mac: [u8; 6],

    /// Destination IP Address
    destination_ip: u32,
}
