from PyQt5.QtCore import pyqtSignal, QCoreApplication, QObject
from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.layers.inet import IP
import re

# get the network interfaces
def get_network_ifaces():
    output = []
    for net, msk, gw, iface, addr, metric in conf.route.routes:
        if_repr = resolve_iface(iface).description
        output.append(if_repr)
    return list(set(output))

# capture class
class PacketCapturer(QObject):
    captureSignal = pyqtSignal(object, int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.running = False
        self.iface = None
        self.packetNo = 0

    def start(self, interface):
        self.iface = interface
        if not self.running:
            self.running = True
            self.run()

    def stop(self):
        self.running = False

    def run(self):
        while self.running:
            sniff(prn=self.callBack, iface=self.iface, store=False, count=1, timeout=5)
            QCoreApplication.processEvents()

    def callBack(self, packet):
        self.packetNo += 1
        nowTime = time.localtime(time.time())
        rcvTime = "{:02}:{:02}:{:02}".format(nowTime[3], nowTime[4], nowTime[5])
        self.captureSignal.emit(packet, self.packetNo, rcvTime)

# parser class
class PacketParser(QObject):
    parseSignal = pyqtSignal(object, list, dict)

    flag = {
            "RRG": 0x20,
            "ACK": 0x10,
            "PSH": 0x08,
            "RST": 0x04,
            "SYN": 0x02,
            "FIN": 0x01
    }

    def __init__(self, format, iface, parent=None):
        super().__init__(parent)
        self.format = format
        self.packetNo = 0
        self.packet = None
        self.iface = iface
        self.firstPacketTime = None
        self.headerPacket = dict.fromkeys(self.format)
        self.treePacket = {}
        self.fragments_cache = {}  # 用于存储分片的缓存

    # parse the packet and make a list
    def parse(self, packet):
        self.packet = packet
        self.headerPacket = dict.fromkeys(self.format)
        self.treePacket = {}
        self.packetNo += 1

        layer = packet
        ptn = re.compile(r"^\s*(\w+)\s*=\s(.*)$", re.M)
        while layer:
            self.treePacket[layer.name] = {}
            rep = layer.show(dump=True)
            index_list = [i.start() for i in re.finditer(r"###\[", rep)]
            endpos = index_list[1] if len(index_list) > 1 else len(rep)
            res = ptn.findall(rep, 0, endpos)
            for f in range(len(res)):
                self.treePacket[layer.name][res[f][0]] = res[f][1]

            if layer.name == "Ethernet":
                self.parseEthernet(layer)
            elif layer.name == "IP":
                self.parseIP(layer)
            elif layer.name == "ARP":
                self.parseARP(layer)
            elif layer.name == "IPv6":
                self.parseIPv6(layer)
            elif layer.name == "TCP":
                self.parseTCP(layer)
            elif layer.name == "UDP":
                self.parseUDP(layer)
            elif layer.name == "ICMP":
                self.parseICMP(layer)
            elif layer.name == "IGMP":
                self.parseIGMP(layer)
            elif layer.name == "DNS":
                self.parseDNS(layer)
            else:
                self.parseHttp(layer)

            layer = layer.payload
        return self.headerPacket, self.treePacket

    def parseEthernet(self, layer):
        self.treePacket["Ethernet"] = {
            "Destination MAC": layer.dst,
            "Source MAC": layer.src,
            "Ethernet Type": hex(layer.type),
        }

        self.headerPacket["Protocol"] = layer.name
        self.headerPacket["Source"] = layer.src
        self.headerPacket["Destination"] = layer.dst
        self.headerPacket["Info"] = hex(layer.type)

    def parseIP(self, layer):
        self.treePacket["IP"] = {
            "Source IP": layer.src,
            "Destination IP": layer.dst,
            "Version": layer.version,
            "Header Length": layer.ihl * 4,
            "Type of Service": layer.tos,
            "Total Length": layer.len,
            "Identification": hex(layer.id),
            "Flags": layer.flags,
            "Fragment Offset": layer.frag,
            "Time to Live": layer.ttl,
            "Protocol": layer.proto,
            "Checksum": hex(layer.chksum),
            "Options": layer.options if layer.options else "None"
        }

        self.headerPacket["Protocol"] = layer.name
        self.headerPacket["Source"] = layer.src
        self.headerPacket["Destination"] = layer.dst

        flags = layer.flags
        is_fragmented = flags.MF or layer.frag > 0
        frag_id = (layer.src, layer.dst, layer.id)
        if is_fragmented:
            self.handle_fragments(layer)
            #  continue parsing if the packet is not the last fragment
            if self.is_all_fragments_received(frag_id) and self.reassemble_fragments(frag_id):
                reassembled_packet = self.reassemble_fragments(frag_id)
                self.parse(reassembled_packet)
            return
        else:
            info = "{} -> {}".format(layer.src, layer.dst)
            self.headerPacket["Info"] = info

    def handle_fragments(self, layer):
        # 为分片创建唯一标识
        frag_id = (layer.src, layer.dst, layer.id)
        if frag_id not in self.fragments_cache:
            self.fragments_cache[frag_id] = []

        # 添加新的分片之前检查是否已存在
        if not any(frag.frag == layer.frag for frag in self.fragments_cache[frag_id]):
            self.fragments_cache[frag_id].append(layer)

        # 检查是否收到所有分片
        if not layer.flags.MF and self.is_all_fragments_received(frag_id):
            # 重组分片
            reassembled_packet = self.reassemble_fragments(frag_id)
            if reassembled_packet:
                # 使用重组后的数据包继续解析
                self.parse(reassembled_packet)

    def is_all_fragments_received(self, frag_id):
        fragments = self.fragments_cache[frag_id]
        # 对分片进行排序
        fragments.sort(key=lambda x: x.frag)
        expected_offset = 0
        for frag in fragments:
            # 检查分片偏移是否匹配预期
            if frag.frag != expected_offset:
                return False
            expected_offset += len(frag) // 8  # 转换为 8 字节块数
        # 检查最后一个分片是否标记了结束
        return not fragments[-1].flags.MF

    def reassemble_fragments(self, frag_id):
        # 对分片进行排序
        fragments = sorted(self.fragments_cache[frag_id], key=lambda x: x.frag)
        # 重组数据包
        reassembled_payload = b''
        for frag in fragments:
            reassembled_payload += bytes(frag.payload)
        # 创建新的 IP 层
        first_fragment = fragments[0]
        reassembled_ip = IP(
            src=first_fragment.src,
            dst=first_fragment.dst,
            proto=first_fragment.proto,
            len=len(reassembled_payload) + 20,
            frag=0,  # 设置片偏移为 0
            flags=0  # 设置标志为未分片
        )
        reassembled_ip.chksum = None  # 让 Scapy 重新计算校验和
        reassembled_packet = reassembled_ip / reassembled_payload
        del self.fragments_cache[frag_id]  # 清除分片缓存
        return reassembled_packet

    def parseARP(self, layer):
        # 更新 headerPacket
        self.headerPacket["Protocol"] = layer.name
        self.headerPacket["Source"] = layer.psrc
        self.headerPacket["Destination"] = layer.pdst
        info = "Who has {}? Tell {}" if layer.op == 1 else "{} is at {}"
        info = info.format(layer.pdst, layer.psrc)
        self.headerPacket["Info"] = info

        self.treePacket["ARP"] = {
            "Hardware Type": layer.hwtype,
            "Protocol Type": layer.ptype,
            "Hardware Size": layer.hwlen,
            "Protocol Size": layer.plen,
            "Opcode": layer.op,
            "Sender MAC Address": layer.hwsrc,
            "Sender IP Address": layer.psrc,
            "Target MAC Address": layer.hwdst,
            "Target IP Address": layer.pdst
        }

    def parseIPv6(self, layer):
        # 更新 headerPacket
        self.headerPacket["Protocol"] = layer.name
        self.headerPacket["Source"] = layer.src
        self.headerPacket["Destination"] = layer.dst

        info = "{} -> {}".format(layer.src, layer.dst)
        self.headerPacket["Info"] = info

        self.treePacket["IPv6"] = {
            "Source IP": layer.src,
            "Destination IP": layer.dst,
            "Traffic Class": layer.tc,
            "Flow Label": layer.fl,
            "Payload Length": layer.plen,
            "Next Header": layer.nh,
            "Hop Limit": layer.hlim
        }

    def parseTCP(self, layer):
        # 更新 headerPacket
        self.headerPacket["Protocol"] = layer.name
        flagList = [flag for flag in self.flag if layer.flags & self.flag[flag]]
        flags = ", ".join(flagList)
        info = "{}->{} [TCP] [{}] Seq={} Ack={} Win={}".format(layer.sport, layer.dport, flags, layer.seq, layer.ack,
                                                               layer.window)
        self.headerPacket["Info"] = info

        self.treePacket["TCP"] = {
            "Source Port": layer.sport,
            "Destination Port": layer.dport,
            "Sequence Number": layer.seq,
            "Acknowledgment Number": layer.ack,
            "Data Offset": layer.dataofs * 4,
            "Reserved": layer.reserved,
            "Flags": flags,
            "Window Size": layer.window,
            "TCP Options": layer.options if layer.options else "None"
        }

    def parseUDP(self, layer):
        # 更新 headerPacket
        self.headerPacket["Protocol"] = layer.name
        info = "{}->{} [UDP] Len={}".format(layer.sport, layer.dport, layer.len)
        self.headerPacket["Info"] = info

        self.treePacket["UDP"] = {
            "Source Port": layer.sport,
            "Destination Port": layer.dport,
            "Length": layer.len
        }

    def parseICMP(self, layer):
        self.headerPacket["Protocol"] = layer.name
        info = "[ICMP]"
        if layer.type == 8:
            info += " Echo Request"
        elif layer.type == 0:
            info += " Echo Reply"
        info += " id={} seq={}".format(layer.id, layer.seq)
        self.headerPacket["Info"] = info

        self.treePacket["ICMP"] = {
            "Type": layer.type,
            "Code": layer.code,
            "Checksum": hex(layer.chksum),
            "ID": layer.id,
            "Sequence": layer.seq
        }

    def parseDNS(self, layer):
        self.headerPacket["Protocol"] = layer.name
        info = "Query " if layer.qr == 0 else "Response "
        info += "id={} op={} rd={} ra={}".format(layer.id, layer.opcode, layer.rd, layer.ra)
        self.headerPacket["Info"] = info

        self.treePacket["DNS"] = {
            "Transaction ID": layer.id,
            "Questions": layer.qdcount,
            "Answers RRs": layer.ancount,
            "Authority RRs": layer.nscount,
            "Additional RRs": layer.arcount,
        }

        # in case DNS flags are not available
        try:
            dns_flags = layer.flags
        except AttributeError:
            dns_flags = None

        self.treePacket["DNS"]["Flags"] = dns_flags

        # 解析 DNS 查询部分
        if layer.qr == 0:  # DNS 查询
            queries = []
            for query in layer.qd:
                query_info = {
                    "Name": query.qname,
                    "Type": query.qtype,
                    "Class": query.qclass
                }
                queries.append(query_info)
            self.treePacket["DNS"]["Queries"] = queries

        # 解析 DNS 响应部分
        elif layer.qr == 1:  # DNS 响应
            answers = []
            for answer in layer.an:
                answer_info = {
                    "Name": answer.rrname,
                    "Type": answer.type,
                    "Class": answer.rclass,
                    "TTL": answer.ttl,
                    "Data": answer.rdata
                }
                answers.append(answer_info)
            self.treePacket["DNS"]["Answers"] = answers

    def parseHttp(self, layer):
        httpFormat = r"(?P<method>GET|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|HEAD)\s(?P<path>.*?)\sHTTP/(?P<version>[\d\.]+)|HTTP/(?P<res_version>[\d\.]+)\s(?P<status_code>\d{3})\s(?P<reason>.*)"
        searchObj = re.search(httpFormat, str(raw(layer[0])))
        if searchObj:
            self.headerPacket["Protocol"] = "HTTP"
            headers = self.parseHttpHeaders(raw(layer[0]))

            if searchObj.group('method'):  # HTTP Request
                self.headerPacket.update({
                    "Info": "Request: {} {}".format(searchObj.group('method'), searchObj.group('path'))
                })
                self.treePacket["HTTP"] = {
                    "Type": "Request",
                    "Method": searchObj.group('method'),
                    "Path": searchObj.group('path'),
                    "Version": searchObj.group('version'),
                    "Headers": headers
                }
            else:  # HTTP Response
                self.headerPacket.update({
                    "Info": "Response: {} {}".format(searchObj.group('status_code'), searchObj.group('reason'))
                })
                self.treePacket["HTTP"] = {
                    "Type": "Response",
                    "Status Code": searchObj.group('status_code'),
                    "Reason": searchObj.group('reason'),
                    "Version": searchObj.group('res_version'),
                    "Headers": headers
                }
            return True
        return False

    def parseHttpHeaders(self, rawData):
        headers = {}
        lines = rawData.decode('utf-8', 'ignore').split('\r\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers

    def headerParse(self, packet):
        if self.packet != packet:
            self.parse(packet)
        return list(self.headerPacket.values())

    def setInterface(self, iface):
        self.iface = iface

    def treeParse(self, packet):
        if self.packet != packet:
            self.parse(packet)
        return self.treePacket

    def handle(self, packet):
        try:
            self.parseSignal.emit(packet, self.headerParse(packet), self.treeParse(packet))
        except Exception as e:
            print(e)
