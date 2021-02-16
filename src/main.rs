use pct::pkt;
use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tap0", tun_tap::Mode::Tap)?;

    let _nic_ip = 0x0a000002_u32;

    // At the moment the IP has to be hardcoded, to implement automatically at some point.

    let mut table = pct::arp::TranslationTable::new();
    pct::eth::nic_init(&mut table);
    let mut buf = [0u8; 1522];

    loop {
        let _data_len = nic.recv(&mut buf)?;
        let pkt = pkt::read_and_reply(&mut buf, _data_len, &mut table);
        if pkt.0 {
            match nic.send(&buf[..pkt.1]) {
                Ok(x) => {
                    println!("Sent data of len {}", x);
                }
                Err(e) => {
                    println!("Error: {:?} in sending data {:X?}", e, buf);
                }
            }
        }
    }
}
