# pct

This is an implementation of TCP in Rust, that I am doing to learn the language!

It makes use of tun/tap devices to implement userspace tcp, which can enable us to do some fun things.

Depends on the tun_tap and etherparse crates.

TODO use IPv4 to parse what protocol it is, which then pass that off into a protcol handler.
