use pct::tcp;
use std::io;
fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tap0", tun_tap::Mode::Tap)?;

    let mut buf = [0u8; 1522];

    for _ in 1..10000 {
        let data_len = nic.recv(&mut buf)?;

        println!("Got {} bytes of data", data_len);

        let frame = tcp::EthernetFrameSlice::read_from_slice(&buf[4..]);
        let header = tcp::EthernetHeader::from_header_slice(&frame);

        let proto = tcp::EtherType::from_u16(header.ethertype);

        let payload = &frame.slice[14..];

        let mut table: pct::arp::TranslationTable = std::collections::HashMap::new();

        match &proto {
            Some(x) => {
                println!("Procotol: {:?}", x);
                if x == &tcp::EtherType::Arp {
                    pct::arp::read_packet(&payload, &mut table);
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
