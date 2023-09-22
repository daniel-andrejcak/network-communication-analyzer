from protocols import protocols #import dictionary obsahujuci protokoly nacitane z externeho suboru

SIZEOFBYTE = 2

class Frame:

    def __init__(self, frame_number, rawPacket):
        self.frame_number = frame_number
        self.length = len(rawPacket)
        self.rawPacket = rawPacket.hex()

        self.makeHexFrame()
        self.makeMACAddr()
        self.determineFrameType()


    #formatuje hex kod aby splnal podmienky vypisu do yaml
    def makeHexFrame(self): 
        self.hexFrame = [self.rawPacket[i:i+2] for i in range(0, len(self.rawPacket), 2)]
        self.hexFrame = '\n'.join([' '.join(self.hexFrame[i:i+16]) for i in range(0, len(self.hexFrame), 16)])

    #extrahuje MAC adresu a vlozi " : " medzi jednotlive byty adresy
    def makeMACAddr(self):         
        self.dstMac = ''.join([self.rawPacket[i:i+SIZEOFBYTE] + ":" for i in range(0, 6*SIZEOFBYTE, 2)])[:-1]
        self.rawPacket = self.rawPacket[6*SIZEOFBYTE:]

        self.srcMac = ''.join([self.rawPacket[i:i+SIZEOFBYTE] + ":" for i in range(0, 6*SIZEOFBYTE, 2)])[:-1]
        self.rawPacket = self.rawPacket[6*SIZEOFBYTE:]

    #urci ci typ ramca
    def determineFrameType(self):
        frameTypeField = self.rawPacket[:2*SIZEOFBYTE]

        frameTypeField = int(frameTypeField, 16)

        if(frameTypeField > 1500):
            self.frameType = "ETHERNET II"

            self.determimeEtherType()


        else:
            self.rawPacket = self.rawPacket[2*SIZEOFBYTE:]

            self.frameType = "IEEE 802.3"
            self.determineIEEE()

    #dalej urci typ IEEE 802.3
    def determineIEEE(self):
        if self.rawPacket[:SIZEOFBYTE] == self.rawPacket[SIZEOFBYTE:2*SIZEOFBYTE] and self.rawPacket[:SIZEOFBYTE] != "ff":
            
            self.frameType += " LLC"

            hexSap = int(self.rawPacket[:SIZEOFBYTE], 16)

            #odstranenie SSAP, DSAP, Control Field
            self.rawPacket = self.rawPacket[3*SIZEOFBYTE:]

            if hexSap == 0xaa:
                self.frameType += " & SNAP"

                #odstranenie Organization code
                self.rawPacket = self.rawPacket[3*SIZEOFBYTE:]

                hexPid = int(self.rawPacket[:2*SIZEOFBYTE], 16)

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

        self.rawPacket = self.rawPacket[20*SIZEOFBYTE:]

        if self.protocol in list(protocols["ipv4_protocol"].keys()):
            self.protocol = protocols["ipv4_protocol"][self.protocol]

            if self.protocol == "TCP": self.getTCPPorts()
            elif self.protocol == "UDP": self.getUDPPorts()

        else:
            self.protocol = "unknown"
        
        #odstrani ip header....ale ipv4 moze byt az 60B, zatial funguje pre 20B, ale 2. byte je header size takze sa to da zistit

        self.formatIPv4(tempSrcIP, tempDstIP)
    
    def getIPFromARP(self):
        tempSrcIP = self.rawPacket[14*SIZEOFBYTE:18*SIZEOFBYTE]
        tempDstIP = self.rawPacket[24*SIZEOFBYTE:28*SIZEOFBYTE]
        
        self.formatIPv4(tempSrcIP, tempDstIP)
   
    def getIPFromIPv6(self):
        tempSrcIP = self.rawPacket[8*SIZEOFBYTE:24*SIZEOFBYTE]
        tempDstIP = self.rawPacket[24*SIZEOFBYTE:40*SIZEOFBYTE]

        self.formatIPv6(tempSrcIP, tempDstIP)

    #prepis IP adries z hex tvaru do normalneho
    #asi sa to takto nema robit, ale to sa domysli casom
    def formatIPv4(self, srcIP, dstIP):
        self.srcIP = str(int(srcIP[0:SIZEOFBYTE], 16)) + '.' + str(int(srcIP[SIZEOFBYTE:2*SIZEOFBYTE], 16)) + '.' + str(int(srcIP[2*SIZEOFBYTE:3*SIZEOFBYTE], 16)) + '.' + str(int(srcIP[3*SIZEOFBYTE:4*SIZEOFBYTE], 16))

        self.dstIP = str(int(dstIP[0:SIZEOFBYTE], 16)) + '.' + str(int(dstIP[SIZEOFBYTE:2*SIZEOFBYTE], 16)) + '.' + str(int(dstIP[2*SIZEOFBYTE:3*SIZEOFBYTE], 16)) + '.' + str(int(dstIP[3*SIZEOFBYTE:4*SIZEOFBYTE], 16))

    #tu sa to da zrobit jak clovek lebo to netreba prepisovat do normalnych cisel, ale staci ked to ostane v hex
    def formatIPv6(self, srcIP, dstIP):
        self.srcIP = ':'.join([srcIP[i:i+4] for i in range(0, len(srcIP), 4)])
        self.dstIP = ':'.join([dstIP[i:i+4] for i in range(0, len(dstIP), 4)])

    #zisti porty, pripadne nazov aplikacneho protokolu
    def getTCPPorts(self):
        self.srcPort = int(self.rawPacket[:2*SIZEOFBYTE], 16)
        self.dstPort = int(self.rawPacket[2*SIZEOFBYTE:4*SIZEOFBYTE], 16)
        
        if self.srcPort in list(protocols["tcp_protocol"].keys()): self.appProtocol = protocols["tcp_protocol"][self.srcPort]
        elif self.dstPort in list(protocols["tcp_protocol"].keys()): self.appProtocol = protocols["tcp_protocol"][self.dstPort]

    def getUDPPorts(self):
        self.srcPort = int(self.rawPacket[:2*SIZEOFBYTE], 16)
        self.dstPort = int(self.rawPacket[2*SIZEOFBYTE:4*SIZEOFBYTE], 16)
        
        if self.srcPort in list(protocols["udp_protocol"].keys()): self.appProtocol = protocols["udp_protocol"][self.srcPort]
        elif self.dstPort in list(protocols["udp_protocol"].keys()): self.appProtocol = protocols["udp_protocol"][self.dstPort]

    #vrati formatovany text vhodny do vystupu
    '''def getFormatedDict(self):
        self.outputDict = {"frame_number" : self.frame_number,
                           "frame_type" : self.frameType,
                           "len_frame_pcap" : self.length,
                           "src_mac" : self.src_mac,
                           "dst_mac" : self.dst_mac,
        }

        return self.outputDict
        
    def getHexFrame(self):
        return {"hexa_frame" : self.hexFrame}'''   
        
