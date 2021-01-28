use pct::tcp;
use std::io;
fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tap0", tun_tap::Mode::Tap)?;

    let mut buf = [0u8; 1522];

    for _ in 1..10000 {
        let data_len = nic.recv(&mut buf)?;

        println!("NEW PACKET!\n\n\n\n");
        println!("Got {} bytes of data", data_len);

        let frame = tcp::EthernetFrameSlice::read_from_slice(&buf[4..]);
        println!("{:x?}", frame);
        println!("ethertype: {:02x}, {:02x}", buf[16], buf[17]);
        let header = tcp::EthernetHeader::from_header_slice(&frame);

        let proto = tcp::EtherType::from_u16(header.ethertype);

        let payload = &frame.slice[14..];

        match &proto {
            Some(x) => {
                println!("Procotol: {:?}", x);
                if x == &tcp::EtherType::Arp {
                    println!("Frame: {:x?}\nPayload: {:x?}", frame, payload);
                    pct::arp::read_packet(&payload);
                }
            }

            None => {
                println!("Bad Protocol. Received Packets: 0x{:x?}", header.ethertype);
                println!("Packet: {:x?}", header);
            }
        }
    }

    Ok(())
}
