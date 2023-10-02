import frame
import argparse
import dpkt
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString
from scapy.all import rdpcap


"""
v trace20 je IEEE 802.3 raw
v trace2 je daco s IEEE 802.3 s LLC
v trace26 je IEEE 802.3 LLC a SNAP

v trace26 82 je ISL
v trace27 325 je LLDP 

v trace27 je 1532 unknown ether type

v trace4 je nekompletna komunikacia - tcp filter
"""

def yamlFormat(packet: frame.Frame, switch=None):
    tempDict = {"frame_number" : packet.frame_number,
            "frame_type" : packet.frameType,
            "len_frame_pcap" : packet.length,
            "len_frame_medium" : max(64, packet.length + 4),
            "src_mac" : packet.srcMac,
            "dst_mac" : packet.dstMac,
        }
    
    if packet.frameType == "IEEE 802.3 LLC":
        tempDict["sap"] = packet.sap
    elif packet.frameType == "IEEE 802.3 LLC & SNAP":
        tempDict["pid"] = packet.pid
    elif packet.frameType == "ETHERNET II":
        tempDict["ether_type"] = packet.etherType

        #vypis len pri prepinaci ARP
        if switch == "ARP": tempDict["arp_opcode"] = packet.opCode

        try:
            tempDict["src_ip"] = packet.srcIP
            tempDict["dst_ip"] = packet.dstIP
        except AttributeError:
            pass

        if packet.etherType == "IPv4":
                
            tempDict["protocol"] = packet.protocol

            try:
                tempDict["src_port"] = packet.srcPort
                tempDict["dst_port"] = packet.dstPort

                try:
                    tempDict["app_protocol"] = packet.appProtocol
                except AttributeError:
                    pass

            except AttributeError:
                pass

    
    tempDict["hexa_frame"] = LiteralScalarString(packet.hexFrame)
    
    
    return tempDict

def IPv4Senders(packetList: list[frame.Frame]):
    uniqueSenders = {}
    for packet in packetList:
        if packet.frameType == "ETHERNET II" and packet.etherType == "IPv4":
            if packet.srcIP in uniqueSenders.keys(): uniqueSenders[packet.srcIP] += 1 
            else: uniqueSenders[packet.srcIP] = 1

    try:
        maxPacketsSent = max(uniqueSenders.values())
    except ValueError:
        pass 

    #vrati vsetky adresy, ktore maju rovnaky - maximalny pocet odoslanych packetov
    addrForMaxPacketSent = [address for address, packetsSent in uniqueSenders.items() if packetsSent == maxPacketsSent]

    return uniqueSenders, addrForMaxPacketSent

#otvorenie pcap suboru a nacitanie jednotlivych packetov do list
def loadFrames():
    frames = rdpcap(PCAPFILE)
    frameList = [bytes(p) for p in frames]


    formatedFrameList = []
    for i in range(0, len(frameList)):
        formatedFrameList.append(frame.Frame(i+1, frameList[i]))

    return formatedFrameList

#zapisanie do suboru yaml
#ak je subor spusteny bez prepinaca - uloha 1. - 3.
def defaultWriteYaml(frameList: list[frame.Frame]):
    yamlFile = open(PCAPFILE[:-5] + ".yaml", "w")
    yaml = YAML()

    data = {'name' : NAME,
            'pcap_name' : PCAPFILE,
            'packets' : [yamlFormat(p) for p in frameList]}

    yaml.dump(data, yamlFile)
    yamlFile.write("\n")

    data = {"ipv4_senders": [{"node": node, "number_of_sent_packets": packets} for node, packets in (IPv4Senders(frameList)[0]).items()]}

    YAML().dump(data, yamlFile)
    yamlFile.write("\n")

    data = {"max_send_packets_by": IPv4Senders(frameList)[1]}

    YAML().dump(data, yamlFile)
    yamlFile.write("\n")


    yamlFile.close()

#doplnenie opcode do ARP packetov
def getOpCode(packet: frame.Frame):
    if int(packet.rawPacket[6*SIZEOFBYTE:8*SIZEOFBYTE]) == 0x0001:
            packet.opCode = "REQUEST"
    elif int(packet.rawPacket[6*SIZEOFBYTE:8*SIZEOFBYTE]) == 0x0002:
        packet.opCode = "REPLY"

    return packet

def arpSwitch(packetList: list[frame.Frame]):
    #vyfiltrovanie ARP packetov
    packetList = [getOpCode(packet) for packet in packetList if (packet.frameType == "ETHERNET II" and packet.etherType == "ARP")]
    
    commsDict = {}
    partialCommsDict = {}

    for packet in packetList:
        if packet.opCode == "REQUEST":
            if commsDict.get(packet.srcIP + " " + packet.dstIP) is None:
                commsDict[packet.srcIP + " " + packet.dstIP] = [packet]

            elif commsDict.get(packet.srcIP + " " + packet.dstIP) is not None:
                #ak je posledny packet v tejto komunikacii REQUEST, znamena to ze nema k sebe REPLY, preto ho odstrani a nahradi aktualnym REQUEST
                if commsDict.get(packet.srcIP + " " + packet.dstIP)[-1].opCode == "REQUEST":
                    partialCommsDict.update({packet.srcIP + " " + packet.dstIP : [commsDict.get(packet.srcIP + " " + packet.dstIP)[-1]]})
                    commsDict.get(packet.srcIP + " " + packet.dstIP)[-1] = packet

                #ak je v komunikacii posledny packet REPLY, tak pridaj do komuniakacie REQUEST
                else:
                    commsDict.get(packet.dstIP + " " + packet.srcIP).append(packet)

        elif packet.opCode == "REPLY":
            #ak najde request v zozname, tak tam priradi reply - kompletna komunikacia
            if commsDict.get(packet.dstIP + " " + packet.srcIP) is not None:
                commsDict.get(packet.dstIP + " " + packet.srcIP).append(packet)

            elif partialCommsDict.get(packet.dstIP + " " + packet.srcIP) is not None:
                (partialCommsDict.get(packet.dstIP + " " + packet.srcIP)).append(packet)

            else:
                partialCommsDict[packet.srcIP + " " + packet.dstIP] = [packet]

    arpWriteYaml(commsDict.values(), partialCommsDict.values())

#vypis do yaml pre prepinac ARP
def arpWriteYaml(comms, partialComms):
    yamlFile = open(PCAPFILE[:-5] + "-ARP.yaml", "w")
    yaml = YAML()

    data = {'name' : NAME,
            'pcap_name' : PCAPFILE,
            "filter_name" : "ARP",
            'complete_comms' : [{"number_comms": i+1, "packets": [yamlFormat(p, "ARP") for p in com]} for i, com in enumerate(comms)]
            }

    yaml.dump(data, yamlFile)
    yamlFile.write("\n")

    temp = {"partial_comms" : [{"number_comms": i+1, "packets": [yamlFormat(p, "ARP") for p in com]} for i, com in enumerate(partialComms)]}

    yaml.dump(temp, yamlFile)

    yamlFile.close()


NAME = "PKS2023/24"
PCAPFILE = "trace-27.pcap"
SIZEOFBYTE = 2

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="zvolte prepinac")
    parser.add_argument("-p", type=str)

    selectedProtocol = parser.parse_args()
    



    frames = loadFrames()

    if selectedProtocol.p is None:
        print("standard yaml output")
        defaultWriteYaml(frames)
    elif selectedProtocol.p == "TCP":
        print("TCP")

    elif selectedProtocol.p == "UDP":
        print("UDP")
    
    elif selectedProtocol.p == "ICMP":
        print("ICMP")
    
    elif selectedProtocol.p == "ARP":
        arpSwitch(frames)

        

    


