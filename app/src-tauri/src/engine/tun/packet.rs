//! Разбор и сборка IPv4-пакетов для userspace-стека TUN.
//!
//! Ядро отдаёт в TUN уже готовые IP-пакеты (без префикса `IFF_NO_PI`) и ждёт
//! обратно тоже IP-пакеты: заголовки, контрольные суммы и порядок полей
//! считаются здесь, а не в стеке.
//!
//! Сознательные ограничения первой версии:
//! * только IPv4 (трафик v6 в TUN не заворачивается, см. `nft.rs`);
//! * фрагментированные пакеты отбрасываются: пересборка — отдельная задача,
//!   а MTU TUN подобран так, чтобы до фрагментации не доходило.

use std::net::Ipv4Addr;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// Разобранный IPv4-пакет. `payload` — всё, что идёт после заголовка.
#[derive(Debug)]
pub struct Ipv4<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub payload: &'a [u8],
}

/// Разбирает IPv4-пакет. `None` — пакет битый, обрезанный или фрагмент;
/// вызывающий просто отбрасывает его (ядро всё равно переспросит).
pub fn parse_ipv4(buf: &[u8]) -> Option<Ipv4<'_>> {
    if buf.len() < 20 || buf[0] >> 4 != 4 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total_len < ihl || total_len > buf.len() {
        return None;
    }
    // MF или ненулевое смещение — фрагмент. Пересборки нет, такие пакеты
    // не обрабатываем: молча пропустить хуже, чем отбросить, поэтому решение
    // фиксируется здесь, а не размазывается по стеку.
    let frag = u16::from_be_bytes([buf[6], buf[7]]);
    if frag & 0x2000 != 0 || frag & 0x1fff != 0 {
        return None;
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    Some(Ipv4 {
        src,
        dst,
        protocol: buf[9],
        ttl: buf[8],
        payload: &buf[ihl..total_len],
    })
}

#[derive(Debug)]
pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(buf: &[u8]) -> Option<Udp<'_>> {
    if buf.len() < 8 {
        return None;
    }
    let len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if len < 8 || len > buf.len() {
        return None;
    }
    Some(Udp {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        payload: &buf[8..len],
    })
}

#[derive(Debug)]
pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    /// Окно, которое объявил собеседник (без масштабирования: мы его не
    /// согласовываем, поэтому масштаб всегда 1).
    pub window: u16,
    /// MSS из опций SYN, если он там был.
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

pub fn parse_tcp(buf: &[u8]) -> Option<Tcp<'_>> {
    if buf.len() < 20 {
        return None;
    }
    let off = (buf[12] >> 4) as usize * 4;
    if off < 20 || buf.len() < off {
        return None;
    }
    let mut mss = None;
    let mut i = 20;
    // Опции разбираем до конца заголовка: kind=0 (EOL), kind=1 (NOP),
    // остальные — kind, len, данные.
    while i + 1 < off {
        let kind = buf[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        let len = buf[i + 1] as usize;
        if len < 2 || i + len > off {
            break;
        }
        if kind == 2 && len == 4 {
            mss = Some(u16::from_be_bytes([buf[i + 2], buf[i + 3]]));
        }
        i += len;
    }
    Some(Tcp {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        flags: buf[13],
        window: u16::from_be_bytes([buf[14], buf[15]]),
        mss,
        payload: &buf[off..],
    })
}

/// Параметры исходящего TCP-сегмента.
pub struct TcpOut<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

/// Собирает IPv4-пакет с UDP. Контрольная сумма считается всегда: нулевое
/// поле формально законно для IPv4, но часть стеков и NAT-устройств на пути
/// относится к такому пакету подозрительно.
pub fn build_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut udp = vec![0u8; len];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let csum = l4_checksum(src, dst, PROTO_UDP, &udp);
    // Ноль в поле суммы означает «не считать»; настоящий ноль передаётся
    // как 0xffff (RFC 768).
    let csum = if csum == 0 { 0xffff } else { csum };
    udp[6..8].copy_from_slice(&csum.to_be_bytes());
    build_ipv4(src, dst, PROTO_UDP, 0, 64, &udp)
}

/// Собирает IPv4-пакет с TCP-сегментом. `mss` добавляет опцию MSS — она нужна
/// только в SYN-ACK.
pub fn build_tcp(src: Ipv4Addr, dst: Ipv4Addr, t: &TcpOut<'_>) -> Vec<u8> {
    let opt_len = if t.mss.is_some() { 4 } else { 0 };
    let hdr_len = 20 + opt_len;
    let seg_len = hdr_len + t.payload.len();
    let mut seg = vec![0u8; seg_len];
    seg[0..2].copy_from_slice(&t.src_port.to_be_bytes());
    seg[2..4].copy_from_slice(&t.dst_port.to_be_bytes());
    seg[4..8].copy_from_slice(&t.seq.to_be_bytes());
    seg[8..12].copy_from_slice(&t.ack.to_be_bytes());
    seg[12] = ((hdr_len / 4) as u8) << 4;
    seg[13] = t.flags;
    seg[14..16].copy_from_slice(&t.window.to_be_bytes());
    // seg[16..18] — контрольная сумма, считается ниже
    // seg[18..20] — указатель срочности, всегда 0
    if let Some(mss) = t.mss {
        seg[20] = 2;
        seg[21] = 4;
        seg[22..24].copy_from_slice(&mss.to_be_bytes());
    }
    seg[hdr_len..].copy_from_slice(t.payload);

    let csum = l4_checksum(src, dst, PROTO_TCP, &seg);
    seg[16..18].copy_from_slice(&csum.to_be_bytes());

    build_ipv4(src, dst, PROTO_TCP, 0, 64, &seg)
}

/// IPv4-заголовок + полезная нагрузка. `flags` — поле flags/fragment offset
/// (0 = можно фрагментировать, 0x4000 = DF).
fn build_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    flags: u16,
    ttl: u8,
    l4: &[u8],
) -> Vec<u8> {
    let total = 20 + l4.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[1] = 0;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&0u16.to_be_bytes());
    p[6..8].copy_from_slice(&flags.to_be_bytes());
    p[8] = ttl;
    p[9] = protocol;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let csum = checksum(&p[..20]);
    p[10..12].copy_from_slice(&csum.to_be_bytes());
    p[20..].copy_from_slice(l4);
    p
}

/// Контрольная сумма Интернета: сумма 16-битных слов в дополнительном коде
/// с переносом бита переполнения и финальной инверсией.
pub fn checksum(data: &[u8]) -> u16 {
    fold(sum16(0, data))
}

/// Контрольная сумма транспортного уровня: псевдозаголовок IPv4 (src, dst,
/// ноль, протокол, длина) + сегмент с нулём в поле суммы.
fn l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = sum16(sum, &src.octets());
    sum = sum16(sum, &dst.octets());
    sum = sum16(sum, &[0, proto]);
    sum = sum16(sum, &(segment.len() as u16).to_be_bytes());
    fold(sum16(sum, segment))
}

fn sum16(mut acc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        acc += (*last as u32) << 8;
    }
    acc
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn parses_ipv4_udp_packet() {
        // Пакет собран независимо на Python (struct + контрольные суммы по RFC),
        // поэтому совпадение доказывает и порядок полей, и арифметику.
        let raw = "45000021000000004011833fc0a8010a5db8d8229c40270f000d012568656c6c6f";
        let bytes = (0..raw.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let pkt = parse_ipv4(&bytes).expect("пакет разобран");
        assert_eq!(pkt.src, ip("192.168.1.10"));
        assert_eq!(pkt.dst, ip("93.184.216.34"));
        assert_eq!(pkt.protocol, PROTO_UDP);
        assert_eq!(pkt.ttl, 64);
        let udp = parse_udp(pkt.payload).expect("UDP разобран");
        assert_eq!(udp.src_port, 40000);
        assert_eq!(udp.dst_port, 9999);
        assert_eq!(udp.payload, b"hello");
    }

    #[test]
    fn builds_udp_packet_byte_for_byte() {
        let pkt = build_udp(
            ip("192.168.1.10"),
            ip("93.184.216.34"),
            40000,
            9999,
            b"hello",
        );
        assert_eq!(
            hex(&pkt),
            "45000021000000004011833fc0a8010a5db8d8229c40270f000d012568656c6c6f"
        );
    }

    #[test]
    fn builds_tcp_syn_with_mss_byte_for_byte() {
        let pkt = build_tcp(
            ip("192.168.1.10"),
            ip("93.184.216.34"),
            &TcpOut {
                src_port: 443,
                dst_port: 51000,
                seq: 1000,
                ack: 0,
                flags: TCP_SYN,
                window: 65535,
                mss: Some(1460),
                payload: &[],
            },
        );
        assert_eq!(
            hex(&pkt),
            "4500002c000000004006833fc0a8010a5db8d82201bbc738000003e8000000006002ffff\
             d3bd0000020405b4"
        );
    }

    #[test]
    fn parses_tcp_segment_with_options() {
        let raw = "4500002c000000004006833fc0a8010a5db8d82201bbc738000003e8000000006002ffff\
                   d3bd0000020405b4";
        let bytes = (0..raw.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let pkt = parse_ipv4(&bytes).expect("пакет разобран");
        let tcp = parse_tcp(pkt.payload).expect("TCP разобран");
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 51000);
        assert_eq!(tcp.seq, 1000);
        assert_eq!(tcp.flags, TCP_SYN);
        assert_eq!(tcp.window, 65535);
        assert_eq!(tcp.mss, Some(1460));
        assert!(tcp.payload.is_empty());
    }

    #[test]
    fn built_checksums_fold_to_zero() {
        // Сумма всех 16-битных слов готового TCP-сегмента вместе с
        // псевдозаголовком обязана давать 0xffff — иначе получатель отбросит
        // сегмент как битый.
        let pkt = build_tcp(
            ip("10.0.0.1"),
            ip("10.0.0.2"),
            &TcpOut {
                src_port: 1234,
                dst_port: 80,
                seq: 7,
                ack: 1,
                flags: TCP_ACK,
                window: 65535,
                mss: None,
                payload: b"GET / HTTP/1.1\r\n",
            },
        );
        let tcp = &pkt[20..];
        let mut sum = 0u32;
        sum = sum16(sum, &pkt[12..16]);
        sum = sum16(sum, &pkt[16..20]);
        sum = sum16(sum, &[0, PROTO_TCP]);
        sum = sum16(sum, &(tcp.len() as u16).to_be_bytes());
        sum = sum16(sum, tcp);
        assert_eq!(fold(sum), 0);

        // Контрольная сумма заголовка IPv4 проверяется так же: сумма с учётом
        // самого поля даёт 0xffff.
        assert_eq!(fold(sum16(0, &pkt[..20])), 0);
    }

    #[test]
    fn truncated_and_fragmented_packets_are_rejected() {
        let good = build_udp(ip("1.2.3.4"), ip("5.6.7.8"), 1, 2, b"x");
        assert!(parse_ipv4(&good).is_some());
        assert!(parse_ipv4(&good[..10]).is_none());
        // total_len больше буфера — обрезанный пакет.
        assert!(parse_ipv4(&good[..good.len() - 1]).is_none());
        // MF-флаг: фрагмент.
        let mut frag = good.clone();
        frag[6] = 0x20;
        assert!(parse_ipv4(&frag).is_none());
        // Ненулевое смещение фрагмента.
        let mut off = good;
        off[7] = 1;
        assert!(parse_ipv4(&off).is_none());
    }

    #[test]
    fn udp_length_shorter_than_payload_is_honoured() {
        // Ядро иногда отдаёт пакет с выравниванием; длина UDP — источник истины.
        let mut pkt = build_udp(ip("1.2.3.4"), ip("5.6.7.8"), 1000, 2000, b"abcdef");
        let total = pkt.len();
        pkt[24..26].copy_from_slice(&(8u16 + 3).to_be_bytes()); // UDP len
        pkt[2..4].copy_from_slice(&((total - 3) as u16).to_be_bytes()); // IP total
        pkt.truncate(total - 3);
        let ip = parse_ipv4(&pkt).unwrap();
        let udp = parse_udp(ip.payload).unwrap();
        assert_eq!(udp.payload, b"abc");
    }
}
