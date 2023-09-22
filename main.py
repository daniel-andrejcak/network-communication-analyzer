import frame
from scapy.all import rdpcap, raw
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

"""
6 bytov je destination MAC adress, 6 bytov je source MAC adress
2 byty je nejaky type (ipv4, arp) !!!POZOR ak je hodnota mensia ako 0x05DC tak je to length a packet je IEEE 802.3 daco a ked je to viac, tak je to Ethernet 2 a hovori to o type IP protokolu
moze byt padding abo trailer abo daco take na koncu

IP -> prve 4 bity su verzia IP, dalsie 4 su header length - to znamena dlzku IP v bytoch
             2. byte je daco
2 byty su dlzka IP + zvysne vrstvy pod (TCP a mozno este daco)
2 byty su nejaky identifikator
2 byty oznacuju fragmentaciu - prve 3 bity urcuju ci sa fragmentuje, zvysok je fragment offset???
4 byty teraz skip - tam sa urci co je "nasledujuci" protokol
IPv4 source (4byty), destination(4byty)

ARP -> 2byty hardware type, 2byty protocol type (IPv4 a tak vole), 1byt hardware size, 1byt protocol size, 2byty OPCode(request, reply, ...), 6byty sender MAC, 4byty sender IP, 6byty target MAC, 4byty target IP

IPv6 -> 4byty ignor, 2byty payload length (velkost od ipv6 header - to co je po ipv6(pre blbcov)), 1byte next header urcuje co nasleduje (napriklad ze dalej je UDP a tak vis jako), 1byte hop limit (netusim),.....(8byte skip)  16byty source adress,  16byty destination adress

LLDP -> 



TCP -> 2byty source port (16^4 = 65536 roznychh portov existuje), 2byty destination port
4byty sequence number ???
4byty acknowledgement number ???
4bity TCP length
12bitov flags (3 su reserved, 9 su nejake flagy)
2 byty nejaky window ???
2 byty TCP checksum
2 byty urgent pointer

UDP -> 2byty source port 2byty destination port 2byty length 2byty checksum

v trace20 je IEEE 802.3 raw
v trace2 je daco s IEEE 802.3 s LLC
v trace26 je IEEE 802.3 LLC a SNAP

v trace26 82 je ISL...a tam sme skoncili a tu je problem chlapci
v trace27 325 je LLDP 

v trace27 je 1532 unknown ether type
"""

def yamlFormat(packet: frame.Frame):
    dict = {"frame_number" : packet.frame_number,
            "frame_type" : packet.frameType,
            "len_frame_pcap" : packet.length,
            "len_frame_medium" : packet.length + 4,
            "src_mac" : packet.srcMac,
            "dst_mac" : packet.dstMac,
        }
    
    if packet.frameType == "IEEE 802.3 LLC":
        dict["sap"] = packet.sap
    elif packet.frameType == "IEEE 802.3 LLC & SNAP":
        dict["pid"] = packet.pid
    elif packet.frameType == "ETHERNET II":
        dict["ether_type"] = packet.etherType

        try:
            dict["src_ip"] = packet.srcIP
            dict["dst_ip"] = packet.dstIP
        except AttributeError:
            pass

        if packet.etherType == "IPv4":
                
            dict["protocol"] = packet.protocol

            try:
                dict["src_port"] = packet.srcPort
                dict["dst_port"] = packet.dstPort
                dict["app_protocol"] = packet.appProtocol
            except AttributeError:
                pass

    
    dict["hexa_frame"] = LiteralScalarString(packet.hexFrame)

    return dict

def loadProtocols():
    PROTOCOLSFILE = "protocols.yaml"

    protocolsFile = open(PROTOCOLSFILE, "r")

    yaml = YAML()

    protocols = dict(yaml.load(protocolsFile))

    protocolsFile.close()

    return protocols

def IPv4Senders(packetList: list[frame.Frame]):
    uniqueSenders = {}
    for packet in packetList:
        if packet.etherType == "IPv4":
            if packet.srcIP in uniqueSenders.keys(): uniqueSenders[packet.srcIP] += 1 
            else: uniqueSenders[packet.srcIP] = 1

    maxPacketsSent = max(uniqueSenders.values())
    #vrati vsetky adresy, ktore maju rovnaky - maximalny pocet odoslanych packetov
    addrForMaxPacketSent = [a for a, value in uniqueSenders.items() if value == maxPacketsSent]

    return uniqueSenders, addrForMaxPacketSent


NAME = "PKS2023/24"
PCAPFILE = "eth-1.pcap"

#nacitanie protokolov z externeho yaml suboru
protocols = loadProtocols()


#otvorenie pcap suboru a nacitanie jednotlivych packetov do list
packets = rdpcap(PCAPFILE)

packetList = [raw(p) for p in packets]

formatedPacketList = []
for i in range(0, len(packetList)):
    formatedPacketList.append(frame.Frame(i+1, packetList[i]))



#formatovanie binarneho tvaru do stringu -> 16bytov v jednom riadku
"""frameHexList = []
for rawPacket in packetList:
    frameHex = [rawPacket.hex()[i:i+2] for i in range(0, len(rawPacket.hex()), 2)]
    frameHex = '\n'.join([' '.join(frameHex[i:i+16]) for i in range(0, len(frameHex), 16)])

    frameHexList.append(LiteralScalarString(frameHex))


#formatovanie do tvaru vhodneho na vypis do yaml suboru
formatedPackets = []
for i in range(0, len(frameHexList)):
    tempDict = {"frame_number": i+1,
                "hexa_frame": frameHexList[i]}
    
    formatedPackets.append(tempDict)"""


#zapisanie do suboru yaml
yamlFile = open(PCAPFILE[:-5] + ".yaml", "w")

yaml = YAML()

packetsSendByNode = [{"node": node, "number_of_sent_packets": packets} for node, packets in (IPv4Senders(formatedPacketList)[0]).items()]


data = {'name' : NAME,
        'pcap_file' : PCAPFILE,
        'packets' : [yamlFormat(p) for p in formatedPacketList],
        "ipv4_senders": [{"node": node, "number_of_sent_packets": packets} for node, packets in (IPv4Senders(formatedPacketList)[0]).items()],
        "max_send_packets_by": IPv4Senders(formatedPacketList)[1]}


yaml.dump(data, yamlFile)

yamlFile.close()