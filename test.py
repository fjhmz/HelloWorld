import ur

BIG_ENDIAN = 'big'
LITTLE_ENDIAN = 'little'

ETH_P_ALL = 0x3

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_RARP = 0x8035
ETH_P_IPV6 = 0x086dd

ETH_TYPE_MAP = {
    ETH_P_IP: 'IP',
    ETH_P_ARP: 'ARP',
    ETH_P_RARP: 'RARP',
    ETH_P_IPV6: 'IPv6'
}


class MACAddress:
    def __init__(self, addr: int):
        self.addr = addr

    def __str__(self):
        return ':'.join('{:02x}'.format(a) for a in self.addr.to_bytes(6, BIG_ENDIAN))

    def __repr__(self):
        return self.__str__()


class EthernetHeader:

    def __init__(self, dst_mac, src_mac):
        self.dst_mac = dst_mac
        self.src_mac = src_mac

    def describe(self):
        return {
            'src_mac': MACAddress(self.src_mac),
            'dst_mac': MACAddress(self.dst_mac)
        }


class EthernetIIHeader(EthernetHeader):

    def __init__(self, dst_mac, src_mac):
        super().__init__(dst_mac, src_mac)
        self.eth_type = 0

    def describe(self):
        dct = super().describe()
        dct['eth_type'] = self._describe_eth_type(self.eth_type)
        return dct

    @staticmethod
    def _describe_eth_type(eth_type):
        if eth_type in ETH_TYPE_MAP:
            return ETH_TYPE_MAP[eth_type]
        return 'Unknown protocol {}'.format(eth_type)


class Ethernet802_3Header(EthernetHeader):

    def __init__(self, dst_mac, src_mac):
        super().__init__(dst_mac, src_mac)
        self.length = 0
        self.llc = 0
        self.snap = 0

    def describe(self):
        dct = super().describe()
        dct['length'] = self.length
        dct['llc'] = self.llc
        dct['snap'] = self.snap
        return dct


def unpack(packet):
    dst_mac = int.from_bytes(packet[:6], BIG_ENDIAN)
    src_mac = int.from_bytes(packet[6:12], BIG_ENDIAN)
    type_or_length = int.from_bytes(packet[12:14], BIG_ENDIAN)
    if type_or_length < 1500:
        hdr = Ethernet802_3Header(dst_mac, src_mac)
        hdr.length = type_or_length
        hdr.llc = int.from_bytes(packet[14:17], BIG_ENDIAN)
        hdr.snap = int.from_bytes(packet[17:22], BIG_ENDIAN)
        return hdr, packet[22:]
    elif type_or_length >= 1536:
        hdr = EthernetIIHeader(dst_mac, src_mac)
        hdr.eth_type = type_or_length
        return hdr, packet[14:]
    else:
        raise ValueError(type_or_length)


def main():
    raw_sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    while True:
        try:
            packet, packet_info = raw_sock.recvfrom(1500)
            eth_header, payload = unpack(packet)
            print(eth_header.describe(), payload)
        except KeyboardInterrupt:
            break
        except ValueError as e:
            print('unpack failed', e)


if __name__ == '__main__':
    main()