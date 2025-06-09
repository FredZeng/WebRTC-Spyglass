from scapy.all import rdpcap
from scapy.layers.inet import UDP
from scapy.layers.rtp import RTP


def filter_rtp_packets_scapy(pcap_path):
    """
    使用 scapy 过滤 pcap 文件中的 RTP 包。
    :param pcap_path: pcap 文件路径
    :return: RTP 包列表（RTP[]）
    """

    def is_rtp(pkt):
        if UDP not in pkt or not hasattr(pkt[UDP], 'payload'):
            return False

        # ignore DNS 53
        # ignore DHCP 67, 68
        # ignore NTP 123
        # ignore mDNS 5353
        # ignore TFTP 69
        # ignore SSDP 1900
        ignore_udp_ports = {53, 67, 68, 123, 5353, 69, 1900}
        if pkt[UDP].dport in ignore_udp_ports or pkt[UDP].sport in ignore_udp_ports:
            return False

        payload = bytes(pkt[UDP].payload)

        if len(payload) < 12:
            return False

        if (payload[0] & 0xC0) != 0x80:
            return False

        pt_rtp = payload[1] & 0x7F
        pt_rtcp = payload[1]

        if pt_rtp >= 128 or (192 <= pt_rtcp <= 230):
            return False

        try:
            rtp = RTP(payload)

            # print("RTP 包解析成功:", pkt[UDP].sport, pkt[UDP].dport)

            return True
        except Exception as e:
            print("解析 RTP 包失败:", e)
            return False

    try:
        packets = rdpcap(pcap_path)
        print('packets:', len(packets))

        lst = []

        for pkt in packets:
            if is_rtp(pkt):
                lst.append(pkt)

        return lst
    except Exception as e:
        print("读取 pcap 文件失败:", e)
        return []


if __name__ == "__main__":
    pass
