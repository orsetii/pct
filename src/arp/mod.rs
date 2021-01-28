use std::collections::HashMap;
use std::convert::TryInto;

///An ARP Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArpPacket {
    /// hardware_type describes what link layer type is used
    /// In our case this will be ethernet - 0x0001
    hardware_type: u16,

    /// proto_type indicates the Protocol Type. In our case this
    /// will be IPv4, which is 0x0800
    proto_type: u16,

    /// hardware_size indicates the size of the hardware field.
    hardware_size: u8,

    /// proto_size indicates the size of the Protocol field.
    proto_size: u8,

    /// opcode declares the type of the ARP message. It can be
    /// an ARP request (1), ARP reply (2), RARP request (3)
    /// or RARP reply (4).
    opcode: u16,

    /// data contains the actual payload of the ARP message, in our case, this will contain IPv4
    /// specific information.
    ipv4_data: ArpIpv4,
}

impl ArpPacket {
    pub fn from_slice(slice: &ArpPacketSlice) -> Self {
        let ipv4_slice = ArpPacketSlice {
            slice: &slice.slice[8..],
        };
        ArpPacket {
            hardware_type: slice.hardware_type(),
            proto_type: slice.proto_type(),
            hardware_size: slice.hardware_size(),
            proto_size: slice.proto_size(),
            opcode: slice.opcode(),
            ipv4_data: ArpIpv4 {
                source_mac: ipv4_slice.source_mac(),
                source_ip: ipv4_slice.source_ip(),
                destination_mac: ipv4_slice.destination_mac(),
                destination_ip: ipv4_slice.destination_ip(),
            },
        }
    }
}

/// For the moment only supporting Ipv4 over Ethernet, meaning the entire packet should be 28
/// bytes. The first 8 are taken by the header, and the rest by this struct!
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArpIpv4 {
    /// Source's MAC Address.
    source_mac: [u8; 6],

    /// Source's IP Address
    source_ip: u32,

    /// Destination's MAC Address
    destination_mac: [u8; 6],

    /// Destination IP Address
    destination_ip: u32,
}

///A slice containing an ARP Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArpPacketSlice<'a> {
    slice: &'a [u8],
}

impl<'a> ArpPacketSlice<'a> {
    /// Using functions to grab this data so we can add to implementations and error/bounds
    /// checking easier.
    fn hardware_type(&self) -> u16 {
        u16::from_be_bytes([self.slice[0], self.slice[1]])
    }

    fn proto_type(&self) -> u16 {
        u16::from_be_bytes([self.slice[2], self.slice[3]])
    }

    fn hardware_size(&self) -> u8 {
        self.slice[4]
    }

    fn proto_size(&self) -> u8 {
        self.slice[5]
    }

    fn opcode(&self) -> u16 {
        u16::from_be_bytes([self.slice[6], self.slice[7]])
    }

    fn source_mac(&self) -> [u8; 6] {
        self.slice[..6]
            .try_into()
            .expect(format!("Error in source MAC {0}:{1}", file!(), line!()).as_str())
    }

    fn source_ip(&self) -> u32 {
        u32::from_be_bytes([self.slice[6], self.slice[7], self.slice[8], self.slice[9]])
    }

    fn destination_mac(&self) -> [u8; 6] {
        self.slice[10..16]
            .try_into()
            .expect(format!("Error in destination MAC {0}:{1}", file!(), line!()).as_str())
    }

    fn destination_ip(&self) -> u32 {
        u32::from_be_bytes([
            self.slice[16],
            self.slice[17],
            self.slice[18],
            self.slice[19],
        ])
    }

    fn read_from_slice(data: &'a [u8; 28]) -> Self {
        ArpPacketSlice { slice: data }
    }
}

// Packet Reception:
// -----------------
//
// When an address resolution packet is received, the receiving
// Ethernet module gives the packet to the Address Resolution module
// which goes through an algorithm similar to the following.
// Negative conditionals indicate an end of processing and a
// discarding of the packet.
//
// ?Do I have the hardware type in ar$hrd?
// Yes: (almost definitely)
//   [optionally check the hardware length ar$hln]
//   ?Do I speak the protocol in ar$pro?
//   Yes:
//     [optionally check the protocol length ar$pln]
//     Merge_flag := false
//     If the pair <protocol type, sender protocol address> is
//         already in my translation table, update the sender
//         hardware address field of the entry with the new
//         information in the packet and set Merge_flag to true.
//     ?Am I the target protocol address?
//     Yes:
//       If Merge_flag is false, add the triplet <protocol type,
//           sender protocol address, sender hardware address> to
//           the translation table.
//       ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
//       Yes:
//         Swap hardware and protocol fields, putting the local
//             hardware and protocol addresses in the sender fields.
//         Set the ar$op field to ares_op$REPLY
//         Send the packet to the (new) target hardware address on
//             the same hardware on which the request was received.
//
// Notice that the <protocol type, sender protocol address, sender
// hardware address> triplet is merged into the table before the
// opcode is looked at.  This is on the assumption that communcation
// is bidirectional; if A has some reason to talk to B, then B will
// probably have some reason to talk to A.  Notice also that if an
// entry already exists for the <protocol type, sender protocol
// address> pair, then the new hardware address supersedes the old
// one.  Related Issues gives some motivation for this.
//
// Generalization:  The ar$hrd and ar$hln fields allow this protocol
// and packet format to be used for non-10Mbit Ethernets.  For the
// 10Mbit Ethernet <ar$hrd, ar$hln> takes on the value <1, 6>.  For
// other hardware networks, the ar$pro field may no longer
// correspond to the Ethernet type field, but it should be
// associated with the protocol whose address resolution is being
// sought.
//
//
//
//
// TODO for ARP module
//
// Store IPv4->MAC translations from broadcasts in our translation table.
//
// When receiving a request, check the table. If found, reply; if not found
// send broadcast, update table with response, and then reply with that translation.
//
//
//
// TODO for reading packet
//
// Enum of hardware types
// Enum of protocol types
// check that protocol/hardware size are valid
// Enum of opcodes
//
//
//

// we
pub type TranslationTable = HashMap<[u8; 6], u32>;

pub fn read_packet(data: &[u8], table: &mut TranslationTable) {
    let packet = ArpPacket::from_slice(&ArpPacketSlice { slice: &data });

    println!("{:02x?}", packet);

    let res = table.get(&packet.ipv4_data.destination_mac);

    match res {
        Some(x) => {
            // If we have a corresponding IP already.
            // TODO implement reply function, and use the IP we grab here.
            println!("Got IP {:?}", x);
        }

        None => {
            println!(
                "No IP Available for MAC {:X?}",
                &packet.ipv4_data.destination_mac
            );
            // TODO implement broadcast to get IP, then reply.
        }
    }
}
