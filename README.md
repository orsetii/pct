# pct

This is an implementation of TCP in Rust, that I am doing to learn the language!

It makes use of tun/tap devices to implement userspace tcp, which can enable us to do some fun things.

Depends on the tun_tap and etherparse crates.

TODO use IPv4 to parse what protocol it is, which then pass that off into a protcol handler.

TODO implement a handling function that goes down the layers of the packet and divides the packet layer and sends off as appropriate. Also each handling function should return a packet to `nic.send()` back, and not be done in the handling functions themself.

EACH PROTO HANDLER TAKES IN ALL LAYERS ABOVE, RETURNS A FULL PAQUETA.

SHOULD LIKE HAVE GENERIC FUNCTIONS TO CONSTRUCT THE PACKET PROBABLY.
