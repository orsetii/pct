use pct::tcp;
use std::convert::TryInto;
use std::io;
fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun2", tun_tap::Mode::Tun)?;

    let mut buf = [0u8; 1522];

    for _ in 1..10000 {
        let data_len = nic.recv(&mut buf)?;

        println!("Got {} bytes of data", data_len);

        let frame = tcp::EthernetFrameSlice::read_from_slice(
            buf[..14].try_into().expect("Couldnt read Eth Frame"),
        );
        println!("etherype: {:02x}, {:02x}", buf[12], buf[13]);
        let header = tcp::EthernetHeader::from_header_slice(&frame);
        println!("Header: {:?}", header);

        let proto = tcp::EtherType::from_u16(header.ethertype);
        match &proto {
            Some(x) => println!("Procotol: {:?}", x),

            None => println!("Bad Protocol. Received Packets: 0x{:x?}", header.ethertype),
        }
    }

    Ok(())
}
