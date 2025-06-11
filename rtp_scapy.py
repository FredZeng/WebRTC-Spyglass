import os.path

from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import UDP
from scapy.layers.rtp import RTP
from scapy.utils import wireshark


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

        return rtp
    except Exception as e:
        print("解析 RTP 包失败:", e)
        return False


def filter_rtp_packets_scapy(pcap_path):
    """
    使用 scapy 过滤 pcap 文件中的 RTP 包。
    :param pcap_path: pcap 文件路径
    :return: RTP 包列表（RTP[]）
    """

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


def replace_rtp_payloads(pcap_a_path, pcap_b_path, output_dir):
    """
    用 B 文件中的 RTP payload 替换 A 文件中的 RTP payload，
    匹配条件：payload type、sequence、timestamp、ssrc
    :param pcap_a_path: A 文件路径
    :param pcap_b_path: B 文件路径
    :param output_dir: 输出目录，如果为 None 则不输出
    :return: 替换后的 A 文件包列表
    """

    pkts_a = []
    pkts_b = []
    # 读取 A、B 文件
    try:
        pkts_a = rdpcap(pcap_a_path)
    except Exception as e:
        print("读取 A 文件失败:", e)

    try:
        pkts_b = rdpcap(pcap_b_path)
    except Exception as e:
        print("读取 B 文件失败:", e)

    print('A packets:', len(pkts_a))
    print('B packets:', len(pkts_b))

    # 构建 B 文件 RTP 包的字典
    rtp_b_dict = {}
    for pkt in pkts_b:
        rtp = is_rtp(pkt)
        if rtp:
            key = (rtp.payload_type, rtp.sequence, rtp.timestamp, rtp.sourcesync)

            if key in rtp_b_dict:
                # 如果已经存在相同的 key，追加到列表中
                # rtp_b_dict[key].append(rtp)
                rtp_b_dict[key].append(pkt[UDP].payload)
            else:
                # rtp_b_dict[key] = [rtp]
                rtp_b_dict[key] = [pkt[UDP].payload]
                pass
            pass

    # 替换 A 文件中的 UDP payload
    new_pkts_a = []
    for pkt in pkts_a:
        rtp = is_rtp(pkt)
        if rtp:
            key = (rtp.payload_type, rtp.sequence, rtp.timestamp, rtp.sourcesync)

            if key in rtp_b_dict and len(rtp_b_dict[key]) > 0:
                top = rtp_b_dict[key].pop(0)

                # udp_origin_payload = bytes(pkt[UDP].payload)
                # print('===')
                # print(' '.join(f'{b:02x}' for b in bytes(top)))
                # print('---')
                # print(' '.join(f'{b:02x}' for b in udp_origin_payload))
                # print('===')

                # 替换 UDP payload
                pkt[UDP].remove_payload()
                pkt[UDP].payload = top
                if hasattr(pkt[UDP], 'len'):
                    del pkt[UDP].len
                if hasattr(pkt[UDP], 'chksum'):
                    del pkt[UDP].chksum
                pass
            pass
        new_pkts_a.append(pkt)

    if output_dir:
        wrpcap(os.path.join(output_dir, 'output.pcap'), new_pkts_a)
        pass

    return new_pkts_a


if __name__ == "__main__":
    replace_rtp_payloads(os.path.expanduser('~/Desktop/2025-06-11T11-52-52/capture.pcap'),
                         os.path.expanduser('~/Desktop/2025-06-11T11-52-52/rtp-dump.pcap'),
                         os.path.expanduser('~/Desktop/2025-06-11T11-52-52'))

    # wireshark(os.path.expanduser('~/Desktop/2025-06-09T11-55-51/output.pcap'))
    pass
