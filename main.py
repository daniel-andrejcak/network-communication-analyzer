import frame
import argparse
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString
from scapy.all import rdpcap



#otvorenie pcap suboru a nacitanie jednotlivych packetov do list
def loadFrames():
    frames = rdpcap(PCAPFILE)
    frameList = [bytes(p) for p in frames]


    formatedFrameList = []
    for i in range(0, len(frameList)):
        formatedFrameList.append(frame.Frame(i+1, frameList[i]))

    return formatedFrameList

#vytvorenie dict s udajmi o kazdom ramci, vo formate vhodnom na vypis do yaml
def yamlFormat(packet: frame.Frame, switch=None):
    tempDict = {"frame_number" : packet.frameNumber,
            "len_frame_pcap" : packet.length,
            "len_frame_medium" : max(64, packet.length + 4),
            "frame_type" : packet.frameType,
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


"""funkcia pre ulohu 3 - este nie je hotova"""
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


#zapisanie do suboru yaml
#ak je subor spusteny bez prepinaca - uloha 1. - 3.
def defaultWriteYaml(frameList: list[frame.Frame]):
    yamlFile = open(PCAPFILE[:-5] + "-output.yaml", "w")
    yaml = YAML()


    data = {'name' : NAME,
            'pcap_name' : PCAPFILE,
            'packets' : [yamlFormat(p) for p in frameList]}

    yaml.dump(data, yamlFile)
    yamlFile.write("\n")

    """vypis pre ulohu 3"""
    ipv4Senders = IPv4Senders(frameList)

    if ipv4Senders[0]: 
        data = {"ipv4_senders":[{"node": node, "number_of_sent_packets": packets} for node, packets in ipv4Senders[0].items()]}
        yaml.dump(data, yamlFile)
        yamlFile.write("\n")

    if ipv4Senders[1]:
        data = {"max_send_packets_by": ipv4Senders[1]}
        yaml.dump(data, yamlFile)
        yamlFile.write("\n")



    yamlFile.close()




def arpSwitch(packetList: list[frame.Frame]):
    #vyfiltrovanie ARP packetov
    packetList = [packet for packet in packetList if (packet.frameType == "ETHERNET II" and packet.etherType == "ARP")]
    
    commsDict = {}
    partialCommsRequest = []
    partialCommsReply = []
    requestReplyPair = []

    for packet in packetList:
        if packet.opCode == "REQUEST":

            #ak nasleduju dve REQUEST po sebe
            if requestReplyPair and requestReplyPair[0].opCode == "REQUEST":
                partialCommsRequest.append(requestReplyPair[0])

            requestReplyPair = [packet]

        elif packet.opCode == "REPLY":

            #ak bol predosly packet request a tento je reply
            if requestReplyPair and requestReplyPair[0].opCode == "REQUEST":
                requestReplyPair.append(packet)

                if not requestReplyPair[0].srcIP + requestReplyPair[0].dstIP in commsDict:
                    commsDict[requestReplyPair[0].srcIP + requestReplyPair[0].dstIP] = []
                commsDict[requestReplyPair[0].srcIP + requestReplyPair[0].dstIP].append(requestReplyPair[0])
                commsDict[requestReplyPair[0].srcIP + requestReplyPair[0].dstIP].append(requestReplyPair[1])
                
                requestReplyPair = []

            #ak po sebe su 2 reply
            else:
                partialCommsReply.append(packet)

    partialComms = partialCommsRequest, partialCommsReply

    arpWriteYaml(commsDict.values(), partialComms)

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

    if partialComms[0] and not partialComms[1]:
        temp = {"partial_comms" : [{"number_comms": 1, "packets": [yamlFormat(p, "ARP") for p in partialComms[0]]}]}
    elif not partialComms[0] and partialComms[1]:
        temp = {"partial_comms" : [{"number_comms": 1, "packets": [yamlFormat(p, "ARP") for p in partialComms[1]]}]}
    else:
        temp = {"partial_comms" : [{"number_comms": 1, "packets": [yamlFormat(p, "ARP") for p in partialComms[0]]}, {"number_comms": 2, "packets": [yamlFormat(p, "ARP") for p in partialComms[1]]}]}

    yaml.dump(temp, yamlFile)

    yamlFile.close()
    

#tftp ma 2 byty header a potom data
def tftpSwitch(packetList: list[frame.Frame]):

    commsDict = {}
    partialCommsDict = {}

    udpPackets = []

    #vyfiltruje vsetky udp packety
    for packet in packetList:
        if packet.frameType == "ETHERNET II" and packet.etherType == "IPv4" and packet.protocol == "UDP":
            udpPackets.append(packet)


    #najde vsetky tftp packety
    tftpPackets = [packet for packet in udpPackets if (hasattr(packet, "appProtocol") and packet.appProtocol == "TFTP")]
    tftpIP = [packet.srcIP + packet.dstIP for packet in tftpPackets]
    tftpDataPorts = []
    index = [] #index bude src a dst port tftp komunikacie
    
    for packet in tftpPackets:
        index.append(packet.srcPort)

        if packet.frameNumber < len(packetList) and packetList[packet.frameNumber].dstPort == packet.srcPort:
            index.append(packetList[packet.frameNumber].srcPort)

            tftpDataPorts.append(index)

            index = []

    #odstrani vsetky ramce pred prvym tftp - netreba ich
    packetList = packetList[tftpPackets[0].frameNumber - 1:]

    comm = []
    index = -1
    ack = False #flag, aby to zobralo aj posledny ack packet v konecnej komunikacii

    for packet in packetList:


        if packet in tftpPackets:
            comm.append(packet)
            index += 1
            size = int(packet.rawPacket[4*SIZEOFBYTE:6*SIZEOFBYTE], 16)

        elif hasattr(packet, "srcPort") and packet.srcPort in tftpDataPorts[index] and packet.dstPort in tftpDataPorts[index]:
            comm.append(packet)
            
            if ack:
                commsDict[str(tftpDataPorts[index][0]) + str(tftpDataPorts[index][1])] = comm
                comm = []

                ack = False

                
            #8 a 9 byte su opcode
            opCode = int(packet.rawPacket[8*SIZEOFBYTE:10*SIZEOFBYTE], 16)

            #error opCode
            if opCode == 0x0005:
                partialCommsDict[str(tftpDataPorts[index][0]) + str(tftpDataPorts[index][1])] = comm
                comm = []

            #ak je packet s mensou velkostou ako prvy packet v tftp komunikacii - ukoncenie komunikacie    
            elif opCode == 0x0003 and int(packet.rawPacket[4*SIZEOFBYTE:6*SIZEOFBYTE], 16) < size:
                ack = True

        


    tftpWriteYaml(commsDict.values(),  partialCommsDict.values())

def tftpWriteYaml(comms, partialComms):
    yamlFile = open(PCAPFILE[:-5] + "-TFTP.yaml", "w")
    yaml = YAML()

    data = {'name' : NAME,
            'pcap_name' : PCAPFILE,
            "filter_name" : "TFTP",
            'complete_comms' : [{"number_comms": i+1, "packets": [yamlFormat(p) for p in com]} for i, com in enumerate(comms)]
            }

    yaml.dump(data, yamlFile)
    yamlFile.write("\n")

    data = {"partial_comms" : [{"number_comms": i+1, "packets": [yamlFormat(p) for p in com]} for i, com in enumerate(partialComms)]}

    yaml.dump(data, yamlFile)

    yamlFile.close()



SIZEOFBYTE = 2
NAME = "PKS2023/24"
#.pcap subor musi byt v rovnakom adresari ako main.py
PCAPFILE = "trace-15.pcap"

if __name__ == '__main__':
    #kod potrebny na fungovanie prepinaca -p !!!este nepouzivat
    parser = argparse.ArgumentParser(description="zvolte prepinac")
    parser.add_argument("-p", type=str)

    selectedProtocol = parser.parse_args()
    
    #nacitanie z pcap suboru
    frames = loadFrames()
    

    #vypis do yaml
    if selectedProtocol.p is None:
        print("standard yaml output")
        defaultWriteYaml(frames)

    #niektore prepinace este nefunguju
    elif selectedProtocol.p == "TCP":
        print("TCP")

    elif selectedProtocol.p == "TFTP":
        print("TFTP")
        tftpSwitch(frames)

    elif selectedProtocol.p == "ICMP":
        print("ICMP")
    
    elif selectedProtocol.p == "ARP":
        print("ARP switch")
        arpSwitch(frames)

        

    


