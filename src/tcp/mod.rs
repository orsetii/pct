use std::convert::TryInto;

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
    slice: &'a [u8],
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

    pub fn read_from_slice(data: &'a [u8; 14]) -> Self {
        EthernetFrameSlice { slice: data }
    }
}
