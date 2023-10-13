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

        
        if packet.etherType == "ARP": tempDict["arp_opcode"] = packet.opCode


        try:
            tempDict["src_ip"] = packet.srcIP
            tempDict["dst_ip"] = packet.dstIP
        except AttributeError:
            pass

        if packet.etherType == "IPv4":
                
            tempDict["protocol"] = packet.protocol
                

            if packet.protocol == "ICMP": tempDict["icmp_type"] = packet.icmpType
        
            #vypis pre ICMP switch
            if switch == "ICMP":
                tempDict["icmp_id"] = packet.id
                tempDict["icmp_seq"] = packet.seq

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
    packetList = [packet for packet in packetList if (packet.frameType == "ETHERNET II" and packet.etherType == "ARP")]

    completeComms = []
    partialRequestComms = []
    partialReplyComms = []

    #request packety uklada do partial request list a ked k nim najde reply, tak ich presunie do complete
    for packet in packetList:
        if packet.opCode == "REQUEST":

            partialRequestComms.append(packet)

        elif packet.opCode == "REPLY":

            for comm in partialRequestComms:

                if packet.srcIP == comm.dstIP:

                    completeComms.append(comm)
                    completeComms.append(packet)

                    partialRequestComms.remove(comm)

                    break
            
            else:

                partialReplyComms.append(packet)



    arpWriteYaml(completeComms, partialRequestComms, partialReplyComms)

def arpWriteYaml(completeComms, partialRequestComms, partialReplyComms):
    yamlFile = open(PCAPFILE[:-5] + "-ARP.yaml", "w")
    yaml = YAML()

    data = {'name' : NAME,
            'pcap_name' : PCAPFILE,
            "filter_name" : "ARP",
            }
    
    yaml.dump(data, yamlFile)
    yamlFile.write("\n")
    
    if completeComms:
        data = {'complete_comms' : [{"number_comms": 1, "packets": [yamlFormat(p) for p in completeComms]}]}

        yaml.dump(data, yamlFile)
        yamlFile.write("\n")
    

    if partialRequestComms and not partialReplyComms:
        data = {"partial_comms" : [{"number_comms": 1, "packets": [yamlFormat(p) for p in partialRequestComms]}]}

    elif partialReplyComms and not partialRequestComms:
        data = {"partial_comms" : [{"number_comms": 1, "packets": [yamlFormat(p) for p in partialReplyComms]}]}
    
    else:
        data = {"partial_comms" : ([{"number_comms": 1, "packets": [yamlFormat(p) for p in partialReplyComms]}], [{"number_comms": 2, "packets": [yamlFormat(p) for p in partialReplyComms]}])}

    yaml.dump(data, yamlFile)
    yamlFile.write("\n")


    yamlFile.close()


#pridat IP do keys pre komunikaciu
def tftpSwitch(packetList: list[frame.Frame]):

    udpPackets = []
    tftpPackets = []

    #vyfiltruje vsetky udp a udp + tftp packety
    for packet in packetList:
        if packet.frameType == "ETHERNET II" and packet.etherType == "IPv4" and packet.protocol == "UDP":
            if (hasattr(packet, "appProtocol") and packet.appProtocol == "TFTP"):
                tftpPackets.append(packet)
                udpPackets.append(packet)
            elif not hasattr(packet, "appProtocol"):
                udpPackets.append(packet)


    comms = {}
    completeComms = {}


    for index, packet in enumerate(udpPackets):
        packet.opCode = int(packet.rawPacket[8*SIZEOFBYTE:10*SIZEOFBYTE], 16)

        if packet in tftpPackets and packet.opCode in (0x01, 0x02):
            if index + 1 < len(udpPackets):
                if udpPackets[index + 1].dstPort == packet.srcPort:
                    comms[(packet.srcPort, udpPackets[index + 1].srcPort)] = [packet]
        
        #ak je to opCode 0x03 - data
        elif packet.opCode == 0x03:
            #najde, ci existuje otvorena komunikacia do ktorej by ho mal pridat
            for key in comms.keys():

                if set(key) == {packet.srcPort, packet.dstPort}:
                    comms[key].append(packet)
                        
        # ak je opCode 0x04 - acknowledgment
        elif packet.opCode == 0x04:
            #najde, ci existuje otvorena komunikacia do ktorej by ho mal pridat
            for key in comms.keys():

                if set(key) == {packet.srcPort, packet.dstPort}:
                    comms[key].append(packet)

                    size = 0

                    #zisti velkost prveho poslaneho datagramu
                    if comms[key][0].opCode == 0x01:

                        if len(key) >= 2:
                            size = int(comms[key][1].rawPacket[4*SIZEOFBYTE:6*SIZEOFBYTE], 16)

                    elif comms[key][0].opCode == 0x02:

                        if len(key) >= 3:
                            size = int(comms[key][2].rawPacket[4*SIZEOFBYTE:6*SIZEOFBYTE], 16)

                    #zisti ci je velkost posledneho pridaneho datagramu mensia ako velkost prveho datagramu - ukoncenie komunikacie
                    if size and int(comms[key][-1].rawPacket[4*SIZEOFBYTE:6*SIZEOFBYTE], 16) < size:
                        
                        completeComms[key] = comms.pop(key)
                        completeComms[key].append(packet)   

                        break 

        
        #ak sa komunikacia konci opCode 0x05 - error, tak ju rovno da do complete communications
        elif packet.opCode == 0x05:

            for key in comms.keys():

                if set(key) == {packet.srcPort, packet.dstPort}:

                    completeComms[key] = comms.pop(key)
                    completeComms[key].append(packet)
                    
                    break

    
    tftpWriteYaml(completeComms.values())


def tftpWriteYaml(comms):
    yamlFile = open(PCAPFILE[:-5] + "-TFTP.yaml", "w")
    yaml = YAML()

    data = {'name' : NAME,
            'pcap_name' : PCAPFILE,
            "filter_name" : "TFTP",
            'complete_comms' : [{"number_comms": i+1, "packets": [yamlFormat(p) for p in com]} for i, com in enumerate(comms)]
            }

    yaml.dump(data, yamlFile)

    yamlFile.close()


def icmpSwitch(packetList: list[frame.Frame]):

    comms = {}
    partialComms = {}


    def placeInPartialComms(packet: frame.Frame, firstIP, secondIP):
        if firstIP + ' ' + secondIP not in partialComms:
            partialComms[firstIP + ' ' + secondIP] = [packet]
        else:
            partialComms[firstIP + ' ' + secondIP].append(packet)



    packetList = [packet for packet in packetList if hasattr(packet, "protocol") and packet.protocol == "ICMP"]

    

    for packet in packetList:
        
        packet.id = int(packet.rawPacket[4*SIZEOFBYTE:6*SIZEOFBYTE], 16)
        packet.seq = int(packet.rawPacket[6*SIZEOFBYTE:8*SIZEOFBYTE], 16)

        if packet.icmpType == "ECHO REQUEST":

            if packet.srcIP + ' ' + packet.dstIP + ' ' + str(packet.id) not in comms:
                comms[packet.srcIP + ' ' + packet.dstIP + ' ' + str(packet.id)] = [[packet]]
                continue
            else:
                comms[packet.srcIP + ' ' + packet.dstIP + ' ' + str(packet.id)].append([packet])
            

        elif packet.icmpType == "ECHO REPLY":
            
            #ked reply packet nema svoju komunikaciu zacatu
            if packet.dstIP + ' ' + packet.srcIP + ' ' + str(packet.id) not in comms:

                placeInPartialComms(packet, packet.dstIP, packet.srcIP)

            #pokusi sa najst request k reply na zaklade identifier a sequence
            else:
                pair = [pair for pair in comms[packet.dstIP + ' ' + packet.srcIP + ' ' + str(packet.id)] if pair[0].seq == packet.seq][0]

                if pair:
                    pair.append(packet)
                else:
                    placeInPartialComms(packet, packet.dstIP, packet.srcIP)

        #pokusi sa najst echo request na ktory odpoveda a da ho do complete communication
        elif packet.icmpType == "Time exceeded":

            #srcIP, identifier a sequence to musi zobrat z encapsulated icmp
            packet.srcIP = packet.rawPacket[24*SIZEOFBYTE:28*SIZEOFBYTE]
            packet.srcIP = '.'.join([str(int(packet.srcIP[i:i+2], 16)) for i in range(0, len(packet.srcIP), 2)])

            packet.id = int(packet.rawPacket[32*SIZEOFBYTE:34*SIZEOFBYTE] , 16)
            
            packet.seq = int(packet.rawPacket[34*SIZEOFBYTE:36*SIZEOFBYTE] , 16)

            if packet.dstIP + ' ' + packet.srcIP + ' ' + str(packet.id) not in comms:

                placeInPartialComms(packet, packet.dstIP, packet.srcIP)

            #pokusi sa najst request ku time exceeded na zaklade identifier a sequence
            else:
                pair = [pair for pair in comms[packet.dstIP + ' ' + packet.srcIP + ' ' + str(packet.id)] if pair[0].seq == packet.seq][0]

                if pair:
                    pair.append(packet)
                else:
                    placeInPartialComms(packet, packet.dstIP, packet.srcIP)

        #obdoba request packetu
        elif packet.icmpType == "Destination unreachable":
            placeInPartialComms(packet, packet.srcIP, packet.dstIP)



    completeComms = {}

    #vyfiltruje samotne request a rozbali request reply pary
    for key in comms.keys():
        for pair in comms[key]:

            if len(pair) == 2:
                if key not in completeComms:
                    completeComms[key] = []

                completeComms[key].append(pair[0])    
                completeComms[key].append(pair[1])    

            else:
                if key not in partialComms:
                    partialComms[key] = []

                partialComms[key].append(pair[0])    


    icmpWriteYaml(completeComms.values(), partialComms.values())

def icmpWriteYaml(comms, partialComms):
    yamlFile = open(PCAPFILE[:-5] + "-ICMP.yaml", "w")
    yaml = YAML()

    data = {'name' : NAME,
            'pcap_name' : PCAPFILE,
            "filter_name" : "ICMP",
            'complete_comms' : [{"number_comms": i+1, "packets": [yamlFormat(p, "ICMP") for p in com]} for i, com in enumerate(comms)]
            }

    yaml.dump(data, yamlFile)
    yamlFile.write("\n")

    if partialComms:
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
        icmpSwitch(frames)
        
    elif selectedProtocol.p == "ARP":
        print("ARP switch")
        arpSwitch(frames)

        

    


