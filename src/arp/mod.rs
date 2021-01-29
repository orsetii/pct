use std::collections::HashMap;
use std::convert::TryInto;
use tun_tap::Iface;

///An ARP Packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArpPacket {
    /// hardware_type describes what link layer type is used
    /// In our case this will be ethernet - 0x0001
    hardware_type: u16,

    /// proto_type indicates the Protocol Type. In our case this
    /// will be MACv4, which is 0x0800
    proto_type: u16,

    /// hardware_size indicates the size of the hardware field.
    hardware_size: u8,

    /// proto_size indicates the size of the Protocol field.
    proto_size: u8,

    /// opcode declares the type of the ARP message. It can be
    /// an ARP request (1), ARP reply (2), RARP request (3)
    /// or RARP reply (4).
    opcode: u16,

    /// data contains the actual payload of the ARP message, in our case, this will contain MACv4
    /// specific information.
    ipv4_data: ArpIpv4,
}

impl ArpPacket {
    pub fn from_slice(slice: &ArpPacketSlice) -> Self {
        let ipv4_slice = ArpPacketSlice {
            slice: &slice.slice,
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

    /// Source's MAC Address
    source_ip: u32,

    /// Destination's MAC Address
    destination_mac: [u8; 6],

    /// Destination MAC Address
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
        self.slice[8..14]
            .try_into()
            .expect(format!("Error in source MAC {0}:{1}", file!(), line!()).as_str())
    }

    fn source_ip(&self) -> u32 {
        u32::from_be_bytes([
            self.slice[14],
            self.slice[15],
            self.slice[16],
            self.slice[17],
        ])
    }

    fn destination_mac(&self) -> [u8; 6] {
        println!("Source MAC Found: {:X?}", &self.slice[18..24]);
        self.slice[18..24]
            .try_into()
            .expect(format!("Error in destination MAC {0}:{1}", file!(), line!()).as_str())
    }

    fn destination_ip(&self) -> u32 {
        u32::from_be_bytes([
            self.slice[24],
            self.slice[25],
            self.slice[26],
            self.slice[27],
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

pub type TranslationTable = HashMap<u32, [u8; 6]>;

pub fn read_packet(
    data: &[u8],
    table: &mut TranslationTable,
    tap: &Iface,
    eth_hdr: &crate::tcp::EthernetFrameSlice,
) {
    let packet_slice = &ArpPacketSlice { slice: &data };
    let packet = ArpPacket::from_slice(packet_slice);

    match packet.opcode {
        0x1 => {
            if packet.ipv4_data.destination_ip == u32::from_be_bytes([0xFF, 0xFF, 0xFF, 0xFF]) {
                // If we get here, we have a broadcast.
                println!("Broadcast Received");
            }
            // We don't need to do that much here,
            // as we implement the rest of the
            // parsing logic after this match.
            println!("ARP Request Received");
            // Lookup MAC in hashtable, attempt to get corresponding MAC
            let res = table.get(&packet.ipv4_data.destination_ip);
            println!(
                "Looked up: {:X?}",
                std::net::Ipv4Addr::from(packet.ipv4_data.destination_ip)
            );
            match res {
                Some(x) => {
                    // If we have a corresponding MAC already.
                    // TODO implement reply function, and use the MAC we grab here.
                    println!(
                        "Got MAC: {:?} for IP {:?}",
                        x,
                        std::net::Ipv4Addr::from(packet.ipv4_data.destination_ip),
                    );
                    reply(packet_slice, *x, tap, eth_hdr);
                }

                None => {
                    println!(
                        "No IP Available for MAC: {:X?}",
                        &packet.ipv4_data.source_mac
                    );
                    // We don't have it stored, and as such don't need to
                    // respond. We can simply wait for a reply, and store that.
                }
            }
        }

        0x2 => {
            // TODO process reply and insert into table.
            println!("ARP Reply Received");
            // Update table with IP and corresponding MAC.
            update_table(
                table,
                packet.ipv4_data.destination_mac,
                packet.ipv4_data.destination_ip,
            );
        }

        _ => {
            eprintln!("Opcode not supported.");
        }
    }
}

fn reply(
    packet_buf: &ArpPacketSlice,
    found_mac: [u8; 6],
    nic: &Iface,
    eth_hdr: &crate::tcp::EthernetFrameSlice,
) {
    assert_eq!(packet_buf.opcode(), 0x1);

    let mut new_packet = [0u8; 28];

    // Copy in hardware type
    new_packet[0] = (packet_buf.hardware_type() >> 8) as u8;
    new_packet[1] = packet_buf.hardware_type() as u8;

    // Copy in protocol type
    new_packet[2] = (packet_buf.proto_type() >> 8) as u8;
    new_packet[3] = packet_buf.proto_type() as u8;

    // Copy in hardware and protcol length
    new_packet[4] = packet_buf.hardware_size();
    new_packet[5] = packet_buf.proto_size();

    // Copy in opcode
    new_packet[6] = 0x00;
    new_packet[7] = 0x02;

    // Store destination mac in buffer as we are
    // overwriting with old source address.
    let new_src_mac = [0xbe, 0xe9, 0x7d, 0x63, 0x31, 0xbc];
    let new_dest_mac: [u8; 6] = packet_buf.source_mac();

    // Change source MAC to our NIC's source mac
    new_packet[8..14].clone_from_slice(&new_src_mac);

    // Change source IP to request packet's source IP
    new_packet[14..18].clone_from_slice(&packet_buf.destination_ip().to_be_bytes());

    // Broadcast!
    new_packet[18..24].clone_from_slice(&new_dest_mac);

    // Change destination IP to request packet's source IP
    new_packet[24..28].clone_from_slice(&packet_buf.slice[14..18]);

    let mut buf = [0u8; 50];

    buf[4..18].clone_from_slice(&eth_hdr.slice[0..14]);
    buf[18..46].clone_from_slice(&new_packet);

    let sent_len = nic.send(&buf);

    println!(
        "Sent ARP reply of size: {0:?} for IP: {1:X?} MAC: {2:X?}",
        sent_len.unwrap(),
        &packet_buf.destination_ip(),
        found_mac
    );
}

// Query HashMap, if not found update.
fn update_table(map: &mut TranslationTable, found_mac: [u8; 6], ip: u32) {
    match map.get(&ip) {
        Some(x) => {
            // got a corresponding IP.
            if *x == found_mac {
                return;
            } else {
                map.insert(ip, found_mac);
            }
        }

        None => {
            map.insert(ip, found_mac);
        }
    }
}
