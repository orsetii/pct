use pct::arp;
use pct::tcp;
use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tap0", tun_tap::Mode::Tap)?;

    let nic_ip = 0x0a000002_u32;

    // At the moment the IP has to be hardcoded, to implement automatically at some point.

    let mut buf = [0u8; 1522];

    for _ in 1..10000 {
        let _data_len = nic.recv(&mut buf)?;
        let frame = tcp::EthernetFrameSlice::read_from_slice(&buf[4..]);
        let header = tcp::EthernetHeader::from_header_slice(&frame);
        let proto = tcp::EtherType::from_u16(header.ethertype);
        let payload = &frame.slice[14..];
        let mut table: pct::arp::TranslationTable = std::collections::HashMap::new();

        tcp::nic_init(&mut table);

        match &proto {
            Some(x) => {
                if x == &tcp::EtherType::Arp {
                    arp::read_packet(&payload, &mut table, &nic, &frame, &nic_ip);
                }
            }

            None => {
                println!("Bad Protocol. Received Packets: 0x{:X?}", header.ethertype);
                println!("Packet: {:X?}", header);
            }
        }
    }

    Ok(())
}
