from protocols import protocols #import dictionary obsahujuci protokoly nacitane z externeho suboru

SIZEOFBYTE = 2

"""trieda sluzi vytvorenie objektov reprezentujuce jednotlive ramce
    metody tejto triedy sluzia na ziskanie informacii(uloha 1, 2) z hexagulasu o jednotlivych ramcoch"""
class Frame:

    def __init__(self, frameNumber, rawPacket):
        self.frameNumber = frameNumber
        self.length = len(rawPacket)
        self.rawPacket = rawPacket.hex()

        self.makeHexFrame()
        self.makeMACAddr()
        self.determineFrameType()


    #formatuje hex kod aby splnal podmienky vypisu do yaml
    def makeHexFrame(self): 
        self.hexFrame = [self.rawPacket[i:i+2] for i in range(0, len(self.rawPacket), 2)]
        self.hexFrame = '\n'.join([' '.join(self.hexFrame[i:i+16]) for i in range(0, len(self.hexFrame), 16)])
        self.hexFrame += "\n" #musi tu byt lebo ho pojebe inak

        self.hexFrame = self.hexFrame.upper()

    #extrahuje MAC adresu a vlozi " : " medzi jednotlive byty adresy
    def makeMACAddr(self):
        #zisti ci obsahuje ISL header a preskoci ho
        if(int(self.rawPacket[:6*SIZEOFBYTE], 16) == 0x01000c000000):
            self.rawPacket = self.rawPacket[26*SIZEOFBYTE:]

        self.dstMac = ''.join([self.rawPacket[i:i+SIZEOFBYTE] + ":" for i in range(0, 6*SIZEOFBYTE, 2)])[:-1]
        self.rawPacket = self.rawPacket[6*SIZEOFBYTE:]

        self.srcMac = ''.join([self.rawPacket[i:i+SIZEOFBYTE] + ":" for i in range(0, 6*SIZEOFBYTE, 2)])[:-1]
        self.rawPacket = self.rawPacket[6*SIZEOFBYTE:]

        self.dstMac = self.dstMac.upper()
        self.srcMac = self.srcMac.upper()

    #urci ci typ ramca
    def determineFrameType(self):
        #toto pole je type(ethernetII) alebo length(ieee802.3)
        frameTypeField = self.rawPacket[:2*SIZEOFBYTE]
        frameTypeField = int(frameTypeField, 16)

        
        if(frameTypeField > 0x5DC):
            #pole type je treba na urcenie ether_type a preto sa neodstrani ako pri ieee 802.3
            self.frameType = "ETHERNET II"
            self.determimeEtherType()

        else:
            #pole length uz netreba, preto sa odstrani
            self.rawPacket = self.rawPacket[2*SIZEOFBYTE:] #

            self.frameType = "IEEE 802.3"
            self.determineIEEE()

    #dalej urci typ IEEE 802.3
    def determineIEEE(self):
        if int(self.rawPacket[:SIZEOFBYTE], 16) != 0xff:
            
            self.frameType += " LLC"

            hexSap = int(self.rawPacket[:SIZEOFBYTE], 16)

            if hexSap == 0xaa:
                self.frameType += " & SNAP"

                hexPid = int(self.rawPacket[6*SIZEOFBYTE:8*SIZEOFBYTE], 16)

                if hexPid in list(protocols["pid"].keys()):
                    self.pid = protocols["pid"][hexPid]
                else:
                    self.pid = "unknown"

                return

            if hexSap in list(protocols["sap"].keys()):
                self.sap = protocols["sap"][hexSap]
            else:
                self.sap = "unknown"
            return
        
        self.frameType += " RAW"

    #urci IP protocol
    def determimeEtherType(self):
        ipType = int(self.rawPacket[:2*SIZEOFBYTE], 16)
        self.rawPacket = self.rawPacket[2*SIZEOFBYTE:]

        if ipType in list(protocols["ether_type"].keys()):
            self.etherType = protocols["ether_type"][ipType]

            if self.etherType == "ARP":
                self.getIPFromARP()
            elif self.etherType == "IPv4":
                self.getIPFromIPv4()
            elif self.etherType == "IPv6":
                self.getIPFromIPv6()
        else: self.etherType = "unknown"

    #funkcie na ziskanie IP z hexagulasu - kazdy protokol ich ma na inom mieste
    def getIPFromIPv4(self):
        #urci protocol ako tcp, udp... doplnit do protocols.yaml
        self.protocol = int(self.rawPacket[9*SIZEOFBYTE:10*SIZEOFBYTE], 16)

        tempSrcIP = self.rawPacket[12*SIZEOFBYTE:16*SIZEOFBYTE]
        tempDstIP = self.rawPacket[16*SIZEOFBYTE:20*SIZEOFBYTE]

        #odstrani ip header, ktory moze byt od 20B do 60B
        headerLength = 4*int(self.rawPacket[1], 16)
        self.rawPacket = self.rawPacket[headerLength*SIZEOFBYTE:]

        if self.protocol in list(protocols["ipv4_protocol"].keys()):
            self.protocol = protocols["ipv4_protocol"][self.protocol]

            if self.protocol == "TCP": self.getTCPPorts()
            elif self.protocol == "UDP": self.getUDPPorts()

        else:
            self.protocol = "unknown"
        

        self.formatIPv4(tempSrcIP, tempDstIP)
    
    def getIPFromARP(self):
        tempSrcIP = self.rawPacket[14*SIZEOFBYTE:18*SIZEOFBYTE]
        tempDstIP = self.rawPacket[24*SIZEOFBYTE:28*SIZEOFBYTE]
        
        self.getOpCode()

        self.formatIPv4(tempSrcIP, tempDstIP)
   
    def getIPFromIPv6(self):
        tempSrcIP = self.rawPacket[8*SIZEOFBYTE:24*SIZEOFBYTE]
        tempDstIP = self.rawPacket[24*SIZEOFBYTE:40*SIZEOFBYTE]

        self.formatIPv6(tempSrcIP, tempDstIP)

    #prepis + format IP adries
    def formatIPv4(self, srcIP, dstIP):
        self.srcIP = '.'.join([str(int(srcIP[i:i+2], 16)) for i in range(0, len(srcIP), 2)])
        self.dstIP = '.'.join([str(int(dstIP[i:i+2], 16)) for i in range(0, len(dstIP), 2)])

    def formatIPv6(self, srcIP, dstIP):
        self.srcIP = ':'.join([srcIP[i:i+4] for i in range(0, len(srcIP), 4)])
        self.dstIP = ':'.join([dstIP[i:i+4] for i in range(0, len(dstIP), 4)])

    #vypise porty, pripadne zisti nazov aplikacneho protokolu
    def getTCPPorts(self):
        self.srcPort = int(self.rawPacket[:2*SIZEOFBYTE], 16)
        self.dstPort = int(self.rawPacket[2*SIZEOFBYTE:4*SIZEOFBYTE], 16)
        
        if self.srcPort in list(protocols["tcp_protocol"].keys()):
            self.appProtocol = protocols["tcp_protocol"][self.srcPort]
        elif self.dstPort in list(protocols["tcp_protocol"].keys()):
            self.appProtocol = protocols["tcp_protocol"][self.dstPort]

    def getUDPPorts(self):
        self.srcPort = int(self.rawPacket[:2*SIZEOFBYTE], 16)
        self.dstPort = int(self.rawPacket[2*SIZEOFBYTE:4*SIZEOFBYTE], 16)
        
        if self.srcPort in list(protocols["udp_protocol"].keys()):
            self.appProtocol = protocols["udp_protocol"][self.srcPort]
        elif self.dstPort in list(protocols["udp_protocol"].keys()): 
            self.appProtocol = protocols["udp_protocol"][self.dstPort]


    def getOpCode(self):
        #doplnenie opcode do ARP packetov
        if int(self.rawPacket[6*SIZEOFBYTE:8*SIZEOFBYTE]) == 0x0001:
                self.opCode = "REQUEST"
        elif int(self.rawPacket[6*SIZEOFBYTE:8*SIZEOFBYTE]) == 0x0002:
            self.opCode = "REPLY"