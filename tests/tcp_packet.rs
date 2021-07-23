extern crate nom;
extern crate pktparse;

mod tests {
    use pktparse::tcp::{TcpOption,WindowScale,MaximumSegmentSize};
    use pktparse::{ipv4, tcp};

    #[test]
    fn parse_tcp_packet() {
        let bytes = [
            0x45, 0x00, 0x00, 0x38, 0x76, 0xf4, 0x40, 0x00, 0x40, 0x06, 0x80, 0xd9, 0xc0, 0xa8,
            0x00, 0x6c, 0xd0, 0x61, 0xb1, 0x7c, 0xb0, 0xc2, 0x00, 0x50, 0xb0, 0xee, 0x32, 0xa6,
            0x04, 0x39, 0xae, 0xe6, 0x50, 0x18, 0x00, 0xe5, 0x76, 0x92, 0x00, 0x00, 0x47, 0x45,
            0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x0a,
        ];

        if let Ok((remaining, _)) = ipv4::parse_ipv4_header(&bytes) {
            if let Ok((remaining, tcp_hdr)) = tcp::parse_tcp_header(remaining) {
                assert_eq!(tcp_hdr.source_port, 45250);
                assert_eq!(tcp_hdr.dest_port, 80);
                assert_eq!(&remaining, b"GET /index.html\x0a");
            } else {
                panic!("can't parse tcp header");
            }
        } else {
            panic!("can't parse ipv4 header");
        }
    }

    #[test]
    fn parse_tcp_packet_with_options() {
        let bytes = [
            0x45, 0x20, 0x00, 0x34, 0x78, 0xd6, 0x40, 0x00, 0x35, 0x06, 0x7e, 0x77, 0x45, 0xa4,
            0x10, 0x00, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x50, 0xc2, 0x27, 0x48, 0xf3, 0x02, 0xc2,
            0x61, 0xd3, 0x16, 0xa8, 0x80, 0x12, 0xff, 0xff, 0x9b, 0x80, 0x00, 0x00, 0x02, 0x04,
            0x05, 0x3a, 0x01, 0x03, 0x03, 0x04, 0x04, 0x02, 0x00, 0x00,
        ];

        if let Ok((remaining, _)) = ipv4::parse_ipv4_header(&bytes) {
            if let Ok((remaining, tcp_hdr)) = tcp::parse_tcp_header(remaining) {
                assert_eq!(tcp_hdr.source_port, 80);
                assert_eq!(tcp_hdr.dest_port, 49703);
                assert_eq!(remaining.len(), 0);

                let options = match tcp_hdr.options {
                    Some(options) => options,
                    None => panic!("no options"),
                };
                let expected : [TcpOption; 5] = [
                    TcpOption::MaximumSegmentSize(MaximumSegmentSize{mss: 1338}),
                    TcpOption::NoOperation,
                    TcpOption::WindowScale(WindowScale{scaling: 4}),
                    TcpOption::SackPermitted,
                    TcpOption::EndOfOptions,
                ];
                for (i, opt) in options.enumerate() {
                    assert_eq!(expected[i], opt)
                }
            } else {
                panic!("can't parse ipv4 header");
            }
        } else {
            panic!("can't parse tcp header");
        }
    }
}
