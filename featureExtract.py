import pyshark
import  csv
from scapy.all import *
import numpy
import datetime
def FeatureExtraction(pcapPath,csvPath):
    caps = rdpcap(pcapPath)
    filteredCaps = pyshark.FileCapture(pcapPath, display_filter="tcp")
    FlowSource =None
    FlowDestination =None
    #print(caps.sessions().keys())
    totalFwdPackets = 0
    totalBwdPackets = 0
    TotalLengthofFwdPackets=0
    TotalLengthofBwdPackets=0
    fwdWindowSize=0
    bwdWindowSize=0
    FlowSourcePort=-1
    FlowDestinationPort=-1
    TotalLengthofFwdHeaders=0
    TotalLengthofBwdHeaders=0
    flowDuration = 0
    Act_data_pkt_forward=0
    lengthofFwdPackets = []
    lengthofBwdPackets = []
    lengthofFlowPackets=[]
    lengthofFwdHeaders = []
    lengthofBwdHeaders = []
    deltaFwd = []
    deltaBwd = []
    deltaFlow = []
    FwdCaps = []
    bwdCaps =[]
    FilterdFwdCaps = []
    FilterdBwdCaps =[]
    flowActive=[]
    flowIdle=[]
    FINFlagCount=0
    SYNFlagCount=0
    RSTFlagCount=0
    PSHFlagCount=0
    ACKFlagCount=0
    URGFlagCount=0
    CWEFlagCount=0
    ECEFlagCount=0
    fwdPSHFlags =0
    bwdPSHFlags =0
    fwdURGFlags =0
    bwdURGFlags =0
    sfLastPacketTS = -1
    sfCount = 0
    sfAcHelper = -1
    threshold=5000000
    min_seg_size_forward=-1
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWE = 0x80
    protocol= 6
    flowPacketNumber=0
    fbulkDuration=0
    fbulkPacketCount=0
    fbulkSizeTotal=0
    fbulkStateCount=0
    fbulkPacketCountHelper=0
    fbulkStartHelper=0
    fbulkSizeHelper=0
    flastBulkTS=0
    bbulkDuration=0
    bbulkPacketCount=0
    bbulkSizeTotal=0
    bbulkStateCount=0
    bbulkPacketCountHelper=0
    bbulkStartHelper=0
    bbulkSizeHelper=0
    blastBulkTS=0
    bAvgBytesPerBulk=0
    bAvgPacketsPerBulk=0
    bAvgBulkRate=0
    fAvgBytesPerBulk=0
    fAvgPacketsPerBulk=0
    fAvgBulkRate=0
    time.strftime("%I:%M")
    time.strftime("%d/%m/%y")
    print(time.strftime("%I:%M"))
    flag = True
    flagBwd= True
    for i,cap in enumerate(caps):
        if TCP in cap:
            if i == 0:

                FwdSource = cap['IP'].src
                FwdDestination = cap['IP'].dst
                FlowSource=FwdSource
                FlowDestination=FwdDestination
                flowStartTime =cap.time*1000000
                flowLastSeen =cap.time*1000000
                startActive=cap.time*1000000
                endActiveTime =cap.time*1000000
                x =cap.time*1000000
    #            timeStamp = datetime.datetime.strptime(str(x/1000), "%a %b %d %H:%M:%S %Y")
                if (sfLastPacketTS == -1):
                    sfLastPacketTS =cap.time*1000000
                    sfAcHelper=cap.time*1000000
                if ((cap.time - (sfLastPacketTS) / 1000000.0) > 1.0):
                    sfCount+=1
                    lastSFduration = (cap.time - sfAcHelper)*1000000
                    currentTime=(cap.time*1000000- sfLastPacketTS)
                    if (currentTime- endActiveTime>threshold):
                        if(endActiveTime - startActive>0):
                            flowActive.append(endActiveTime - startActive)
                        flowIdle.append(currentTime-endActiveTime)
                        endActiveTime=currentTime
                        startActive=currentTime
                    else:
                        endActiveTime=currentTime
                    sfAcHelper=cap.time*1000000
                sfLastPacketTS=cap.time*1000000

                #forwardBytes+=packet.getPayloadBytes()
            else:
                if (cap['IP'].src == FwdSource and cap['IP'].dst == FwdDestination):
                    FwdCaps.append(cap)
                if (cap['IP'].dst == FwdSource and cap['IP'].src == FwdDestination):
                    bwdCaps.append(cap)
                deltaFlow.append(abs(cap.time*1000000 - flowLastSeen))
                flowLastSeen= cap.time*1000000
            flowPacketNumber+=1


    for i,filteredCap in enumerate (filteredCaps):
        lengthofFlowPackets.append(int(filteredCaps[i].length))

        #FwdFlow
        if filteredCap['ip'].src == FwdSource and filteredCap['ip'].dst == FwdDestination:
            if(i == 0):
                FlowSourcePort = filteredCap[filteredCap.transport_layer].srcport
                FlowDestinationPort = filteredCap[filteredCap.transport_layer].dstport
            FilterdFwdCaps.append(filteredCap)
        #BwdFlow
        if filteredCap['ip'].src ==  FwdDestination and filteredCap['ip'].dst == FwdSource:
            FilterdBwdCaps.append(filteredCap)


    if len(deltaFlow)!= 0:
        flowIATTotal= sum(deltaFlow)
        flowIATMean= numpy.mean(deltaFlow)
        flowIATStd=numpy.std(deltaFlow,ddof=1)
        flowIATMax= max(deltaFlow)
        flowIATMin=min(deltaFlow)
        flowDuration=(flowLastSeen-flowStartTime)
    else:
        flowDuration=0
        flowIATStd=0
        flowIATMin=0
        flowIATMean=0
        flowIATMax=0



    for i,filteredCap in enumerate (FilterdFwdCaps):
        lengthofFwdPackets.append(int(FilterdFwdCaps[i].length))
        if int(FilterdFwdCaps[i].length)>= 1 :
            Act_data_pkt_forward+=1


    for i,cap in enumerate(FwdCaps):
          if TCP in cap:

                size = lengthofFwdPackets[i]
                if flag == True:
                    if (blastBulkTS > fbulkStartHelper):
                        fbulkStartHelper = 0
                    if (size <= 0):
                        flag=False
                    lengthofFwdPackets[i]+=1
                    if (fbulkStartHelper == 0):
                        fbulkStartHelper = cap.time*1000000
                        fbulkPacketCountHelper = 1
                        fbulkSizeHelper = size
                        flastBulkTS = cap.time*1000000
                    else :
                        if ((cap.time*1000000 - flastBulkTS) / 1000000.0 > 1.0):
                            fbulkStartHelper = cap.time*1000000
                            flastBulkTS = cap.time*1000000
                            fbulkPacketCountHelper = 1
                            fbulkSizeHelper = size

                        else:
                            fbulkPacketCountHelper += 1
                            fbulkSizeHelper += size

                            if (fbulkPacketCountHelper == 4):
                                fbulkStateCount += 1
                                fbulkPacketCount += fbulkPacketCountHelper
                                fbulkSizeTotal += fbulkSizeHelper
                                fbulkDuration += cap.time * 1000000 - fbulkStartHelper
                            if (fbulkPacketCountHelper > 4):
                                fbulkPacketCount += 1
                                fbulkSizeTotal += size
                                fbulkDuration += cap.time*1000000 - flastBulkTS

                            flastBulkTS = cap.time*1000000


                if(i ==0):
                    fwdWindowSize = cap[TCP].window
                    F = cap['TCP'].flags
                    if F & PSH:
                        fwdPSHFlags += 1
                    if F & URG:
                        fwdURGFlags += 1
                if i != 0:
                    forwardLastSeen = FwdCaps[i - 1].time*1000000
                    deltaFwd.append(abs(cap.time*1000000-forwardLastSeen))
                    F = cap['TCP'].flags
                    if F & FIN:
                        FINFlagCount += 1
                    if F & SYN:
                        SYNFlagCount += 1
                    if F & RST:
                        RSTFlagCount += 1
                    if F & PSH:
                        PSHFlagCount += 1
                    if F & ACK:
                        ACKFlagCount += 1
                    if F & URG:
                        URGFlagCount += 1
                    if F & ECE:
                        ECEFlagCount += 1
                    if F & CWE:
                        CWEFlagCount += 1
                if (sfLastPacketTS == -1):
                    sfLastPacketTS =cap.time*1000000
                    sfAcHelper=cap.time*1000000
                if ((cap.time - (sfLastPacketTS) / 1000000.0) > 1.0):
                    sfCount+=1
                    lastSFduration = (cap.time - sfAcHelper)*1000000
                    currentTime=(cap.time*1000000- sfLastPacketTS)
                    if (currentTime- endActiveTime>threshold):
                        if(endActiveTime - startActive>0):
                            flowActive.append(endActiveTime - startActive)
                        flowIdle.append(currentTime-endActiveTime)
                        endActiveTime=currentTime
                        startActive=currentTime
                    else:
                        endActiveTime=currentTime
                    sfAcHelper=cap.time*1000000
                sfLastPacketTS=cap.time*1000000
                c =  cap.show(dump = True)

                word= "len"
                index = c.find(word)
                if c[index+12:index+16] !='    ':
                  lengthofFwdHeaders.append(int(c[index+12:index+16]))
                  TotalLengthofFwdHeaders+=int(c[index+12:index+16])
                  totalFwdPackets +=1
                else:
                    lengthofFwdHeaders.append(0)
                if i ==0:
                    min_seg_size_forward= int(c[index+12:index+16])
                else:
                    min_seg_size_forward =min(min_seg_size_forward,int(c[index+12:index+16]))
    if flowDuration!=0:
      fwdPacketsPerSecond=totalFwdPackets/(flowDuration/1000000)
    else:
        fwdPacketsPerSecond=0
    if sfCount != 0:
     subFlowFwdPackets=totalFwdPackets/sfCount
    else:
      subFlowFwdPackets=0
    if len(deltaFwd) !=0:
         FwdIATTotal= sum(deltaFwd)
         FwdIATMean= numpy.mean(deltaFwd)
         FwdIATStd=numpy.std(deltaFwd,ddof=1)
         FwdIATMax= max(deltaFwd)
         FwdIATMin=min(deltaFwd)
    else:
        FwdIATTotal=0
        FwdIATMax=0
        FwdIATMean=0
        FwdIATMin=0
        FwdIATStd=0


    for i,filteredCap in enumerate (FilterdBwdCaps):
        lengthofBwdPackets.append(int(FilterdBwdCaps[i].length))

    for i,cap in enumerate(bwdCaps):
          if TCP in cap:
                size = lengthofBwdPackets[i]
                if flagBwd == True:
                  if (flastBulkTS > bbulkStartHelper):
                      bbulkStartHelper = 0
                  if (size <= 0):
                      flagBwd = False
                  lengthofBwdPackets[i] += 1
                  if (bbulkStartHelper == 0):
                      bbulkStartHelper = cap.time * 1000000
                      bbulkPacketCountHelper = 1
                      bbulkSizeHelper = size
                      blastBulkTS = cap.time * 1000000
                  else:
                      if ((cap.time * 1000000 - blastBulkTS) / 1000000.0 > 1.0):
                          bbulkStartHelper = cap.time * 1000000
                          blastBulkTS = cap.time * 1000000
                          bbulkPacketCountHelper = 1
                          bbulkSizeHelper = size

                      else:
                          bbulkPacketCountHelper += 1
                          bbulkSizeHelper += size

                          if (bbulkPacketCountHelper == 4):
                              bbulkStateCount += 1
                              bbulkPacketCount += bbulkPacketCountHelper
                              bbulkSizeTotal += bbulkSizeHelper
                              bbulkDuration += cap.time * 1000000 - bbulkStartHelper
                          if (bbulkPacketCountHelper > 4):
                              bbulkPacketCount += 1
                              bbulkSizeTotal += size
                              bbulkDuration += cap.time * 1000000 - flastBulkTS

                          flastBulkTS = cap.time * 1000000

                if (i == 0):
                  bwdWindowSize = cap[TCP].window
                  F = cap['TCP'].flags
                  if F & PSH:
                      fwdPSHFlags += 1
                  if F & URG:
                      fwdURGFlags += 1
                if i != 0:
                    backwardLastSeen = bwdCaps[i - 1].time*1000000
                    deltaBwd.append(abs(cap.time*1000000-backwardLastSeen))
                    F = cap['TCP'].flags
                    if F & FIN:
                        FINFlagCount += 1
                    if F & SYN:
                        SYNFlagCount += 1
                    if F & RST:
                        RSTFlagCount += 1
                    if F & PSH:
                        PSHFlagCount += 1
                        bwdPSHFlags += 1
                    if F & ACK:
                        ACKFlagCount += 1
                    if F & URG:
                        URGFlagCount += 1
                        bwdURGFlags += 1
                    if F & ECE:
                        ECEFlagCount += 1
                    if F & CWE:
                        CWEFlagCount += 1
                if (sfLastPacketTS == -1):
                    sfLastPacketTS =cap.time*1000000
                    sfAcHelper=cap.time*1000000
                if ((cap.time - (sfLastPacketTS) / 1000000.0) > 1.0):
                    sfCount+=1
                    lastSFduration = (cap.time - sfAcHelper)*1000000
                    currentTime=(cap.time*1000000- sfLastPacketTS)
                    if (currentTime- endActiveTime>threshold):
                        if(endActiveTime - startActive>0):
                            flowActive.append(endActiveTime - startActive)
                        flowIdle.append(currentTime-endActiveTime)
                        endActiveTime=currentTime
                        startActive=currentTime
                    else:
                        endActiveTime=currentTime
                    sfAcHelper=cap.time*1000000
                sfLastPacketTS=cap.time*1000000
                c =  cap.show(dump = True)
                word= "len"
                index = c.find(word)
                if c[index+12:index+16] !='    ':
                  lengthofFwdHeaders.append(int(c[index+12:index+16]))
                  TotalLengthofBwdHeaders+=int(c[index+12:index+16])
                  totalBwdPackets +=1



    if (fbulkStateCount != 0):
        fAvgBytesPerBulk = fbulkSizeTotal/fbulkStateCount

    if (fbulkStateCount != 0):
        fAvgPacketsPerBulk = fbulkPacketCount/fbulkStateCount

    if (fbulkDuration != 0 ):
        fAvgBulkRate =fbulkSizeTotal/(fbulkDuration/1000000)

    if (bbulkStateCount != 0):
        bAvgBytesPerBulk = bbulkSizeTotal/bbulkStateCount

    if (bbulkStateCount != 0):
        bAvgPacketsPerBulk = bbulkPacketCount/bbulkStateCount

    if (bbulkDuration != 0 ):
        bAvgBulkRate =bbulkSizeTotal/(bbulkDuration/1000000)

    if (flowDuration != 0 ):
        bwdPacketsPerSecond=totalBwdPackets/(flowDuration/1000000)
    else:
        bwdPacketsPerSecond=0
    if len(deltaBwd)!=0:
        bwdIATTotal= sum(deltaBwd)
        bwdIATMean= numpy.mean(deltaBwd)
        bwdIATStd=numpy.std(deltaBwd,ddof=1)
        bwdIATMax= max(deltaBwd)
        bwdIATMin=min(deltaBwd)
    else:
        bwdIATMax=0
        bwdIATMean=0
        bwdIATMin=0
        bwdIATStd=0
        bwdIATTotal=0
    if sfCount!=0:
      subFlowBwdPackets=totalBwdPackets/sfCount
    else:
       subFlowBwdPackets=0

    if  sfCount!=0:
      subFlowFwdBytes=TotalLengthofFwdPackets/sfCount
    else:
        subFlowFwdBytes=0

    if totalBwdPackets!=0:
      downUpRatio= totalBwdPackets/totalFwdPackets
    else:
        downUpRatio=0


    minPacketLength=min(lengthofFlowPackets)
    maxPacketLength=max(lengthofFlowPackets)
    packetLengthMean =numpy.mean(lengthofFlowPackets)
    packetLengthStd =numpy.std(lengthofFlowPackets,ddof=1)
    packetLengthvar =numpy.var(lengthofFlowPackets,ddof=1)
    if flowPacketNumber!=0 :
      avgPacketSize=sum(lengthofFlowPackets)/flowPacketNumber
    else:
        avgPacketSize=0

    if  len(lengthofFwdPackets)  != 0:
        TotalLengthofFwdPackets = sum (lengthofFwdPackets)
        MaxLengthofFwdPackets= max(lengthofFwdPackets)
        MinLengthofFwdPackets=min(lengthofFwdPackets)
        FwdPacketLengthMean= numpy.mean(lengthofFwdPackets)
        FwdPacketLengthStd=numpy.std(lengthofFwdPackets,ddof=1)
    else:
        TotalLengthofFwdPackets=0
        MaxLengthofFwdPackets=0
        MinLengthofFwdPackets=0
        FwdPacketLengthMean=0
        FwdPacketLengthStd=0

    if totalFwdPackets!=0:
        fwdAvgSegmentSize=TotalLengthofFwdPackets/totalFwdPackets
    else :                 
        fwdAvgSegmentSize=0
    if  len(lengthofBwdPackets)  != 0:
        TotalLengthofBwdPackets = sum (lengthofBwdPackets)
        MaxLengthofBwdPackets= max(lengthofBwdPackets)
        MinLengthofBwdPackets=min(lengthofBwdPackets)
        bwdPacketLengthMean= numpy.mean(lengthofBwdPackets)
        bwdPacketLengthStd=numpy.std(lengthofBwdPackets,ddof=1)
    else:
        TotalLengthofBwdPackets=0
        MaxLengthofBwdPackets=0
        MinLengthofBwdPackets=0
        bwdPacketLengthMean=0
        bwdPacketLengthStd=0



    if totalBwdPackets!=0:
      bwdAvgSegmentSize=TotalLengthofBwdPackets/totalBwdPackets
    else :
        bwdAvgSegmentSize=0
    if  sfCount!=0:
      subFlowBwdBytes=TotalLengthofBwdPackets/sfCount
    else:
        subFlowBwdBytes=0
    FlowID = FlowSource+ '-'+ FlowDestination+'-'+FlowSourcePort+'-'+FlowDestinationPort+'-'+ str(protocol)
    if flowDuration!=0:
        packetdPerSecond=flowPacketNumber/flowDuration
        bytePerSecond=(TotalLengthofFwdHeaders+TotalLengthofBwdHeaders)/flowDuration
    else:
        bytePerSecond = 0
        packetdPerSecond=0
    if len(flowActive)!= 0:
        activeMean=numpy.mean(flowActive)
        activeStd = numpy.std(flowActive,ddof=1)
        activeMax = max(flowActive)
        activeMin = min(flowActive)
    else:
        activeMax=0
        activeMean=0
        activeMin=0
        activeStd=0
    if len(flowIdle)!= 0:
        idleMean=numpy.mean(flowIdle)
        idleStd = numpy.std(flowIdle,ddof=1)
        idleMax = max(flowIdle)
        idleMin = min(flowIdle)
    else:
        idleMax=0
        idleMean=0
        idleMin=0
        idleStd=0

    with open(csvPath, 'w') as myfile:
        wr = csv.writer(myfile)
        fieldnames = ['Flow ID','Source IP','Source Port','Destination IP','Destination Port','Protocol','Flow Duration',
                      'Total Fwd Packets', 'Total Bwd Packets', 'Total Length of Fwd Packets','Total Length of Bwd Packets',
                      'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean','Fwd Packet Length Std',
                      'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean','Bwd Packet Length Std',
                      'Fwd Packets/s','Bwd Packets/s',
                      'Flow Bytes/s','Flow Packets/s',
                      'Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min',
                      'Fwd IAT Total','Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
                      'Bwd IAT Total','Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
                      'Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags',
                      'Fwd Header Length', 'Bwd Header Length',
                      "Pkt Len Min","Pkt Len Max","Pkt Len Mean","Pkt Len Std","Pkt Len Var",
                      'FIN Flag Count','SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
                      'CWE Flag Count', 'ECE Flag Count','Down/Up Ratio','Average Packet Size',' Avg Fwd Segment Size',' Avg Bwd Segment Size',
                      'Fwd Avg Bytes/Bulk',' Fwd Avg Packets/Bulk',' Fwd Avg Bulk Rate',' Bwd Avg Bytes/Bulk',' Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate',
                      'Subflow Fwd Packets',' Subflow Fwd Bytes',' Subflow Bwd Packets',' Subflow Bwd Bytes','Init_Win_bytes_forward',
                      ' Init_Win_bytes_backward',' act_data_pkt_fwd',' min_seg_size_forward',
                      'Active Mean',' Active Std',' Active Max',' Active Min',
                      'Idle Mean',' Idle Std',' Idle Max',' Idle Min']
        writer = csv.DictWriter(myfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(
            {            'Flow ID':FlowID,
                         'Source IP':FlowSource,
                         'Source Port':FlowSourcePort,
                         'Destination IP':FlowDestination,
                         'Destination Port':FlowDestinationPort,
                         'Protocol': protocol,
                         'Flow Duration': flowDuration,
                         'Total Fwd Packets': totalFwdPackets,
                         'Total Bwd Packets': totalBwdPackets,
                         'Total Length of Fwd Packets':TotalLengthofFwdPackets,
                         'Total Length of Bwd Packets':TotalLengthofBwdPackets,
                         'Fwd Packet Length Max':MaxLengthofFwdPackets,
                         'Fwd Packet Length Min':MinLengthofFwdPackets,
                         'Fwd Packet Length Mean':FwdPacketLengthMean,
                          'Fwd Packet Length Std':FwdPacketLengthStd,
                          'Bwd Packet Length Max':MaxLengthofBwdPackets,
                          'Bwd Packet Length Min':MinLengthofBwdPackets,
                          'Bwd Packet Length Mean':bwdPacketLengthMean,
                          'Bwd Packet Length Std':bwdPacketLengthStd,
                          'Flow Bytes/s':bytePerSecond,
                          'Flow Packets/s':packetdPerSecond,
                          'Flow IAT Mean':flowIATMean,
                          'Flow IAT Std':flowIATStd,
                          'Flow IAT Max':flowIATMax,
                          'Flow IAT Min':flowIATMin,
                          'Fwd IAT Total':FwdIATTotal,
                          'Fwd IAT Mean':FwdIATMean,
                          'Fwd IAT Std':FwdIATStd,
                          'Fwd IAT Max':FwdIATMax,
                          'Fwd IAT Min':FwdIATMin,
                          'Bwd IAT Total':bwdIATTotal,
                          'Bwd IAT Mean':bwdIATMean,
                          'Bwd IAT Std':bwdIATStd,
                          'Bwd IAT Max':bwdIATMax,
                          'Bwd IAT Min':bwdIATMin,
                          'Fwd PSH Flags':fwdPSHFlags,
                          'Bwd PSH Flags':bwdPSHFlags,
                          'Fwd URG Flags': fwdURGFlags,
                          'Bwd URG Flags': bwdURGFlags,
                          'Fwd Header Length':TotalLengthofFwdHeaders,
                          'Bwd Header Length':TotalLengthofBwdHeaders,
                          'Fwd Packets/s':fwdPacketsPerSecond,
                          'Bwd Packets/s':bwdPacketsPerSecond,
                          "Pkt Len Min":minPacketLength,
                          "Pkt Len Max":maxPacketLength,
                          "Pkt Len Mean":packetLengthMean,
                          "Pkt Len Std":packetLengthStd,
                          "Pkt Len Var":packetLengthvar,
                          'FIN Flag Count':FINFlagCount,
                          'SYN Flag Count':SYNFlagCount,
                          'RST Flag Count':RSTFlagCount,
                          'PSH Flag Count':PSHFlagCount,
                          'ACK Flag Count':ACKFlagCount,
                          'URG Flag Count':URGFlagCount,
                          'CWE Flag Count':CWEFlagCount,
                          'ECE Flag Count':ECEFlagCount,
                          'Down/Up Ratio':downUpRatio,
                          'Average Packet Size':avgPacketSize,
                          ' Avg Fwd Segment Size':fwdAvgSegmentSize,
                          ' Avg Bwd Segment Size':bwdAvgSegmentSize,
                          'Fwd Avg Bytes/Bulk':fAvgBytesPerBulk,
                          ' Fwd Avg Packets/Bulk':fAvgPacketsPerBulk,
                          ' Fwd Avg Bulk Rate':fAvgBulkRate,
                          ' Bwd Avg Bytes/Bulk':bAvgBytesPerBulk,
                          ' Bwd Avg Packets/Bulk':bAvgPacketsPerBulk,
                          'Bwd Avg Bulk Rate':bAvgBulkRate,
                          'Subflow Fwd Packets':subFlowFwdPackets,
                          ' Subflow Fwd Bytes':subFlowFwdBytes,
                          ' Subflow Bwd Packets':subFlowBwdPackets,
                          ' Subflow Bwd Bytes':subFlowBwdBytes,
                          'Init_Win_bytes_forward':fwdWindowSize,
                          ' Init_Win_bytes_backward':bwdWindowSize,
                          ' act_data_pkt_fwd':Act_data_pkt_forward,
                          ' min_seg_size_forward':min_seg_size_forward,
                          'Active Mean':activeMean,
                         ' Active Std':activeStd,
                         ' Active Max':activeMax,
                         ' Active Min':activeMin,
                         'Idle Mean':idleMean,
                         ' Idle Std':idleStd,
                         ' Idle Max':idleMax,
                         ' Idle Min':idleMin })
        features = numpy.array([flowDuration,totalFwdPackets,totalBwdPackets,TotalLengthofFwdPackets,TotalLengthofBwdPackets,MaxLengthofFwdPackets,MinLengthofFwdPackets,
                                FwdPacketLengthMean,FwdPacketLengthStd,MaxLengthofBwdPackets,MinLengthofBwdPackets,bwdPacketLengthMean,bwdPacketLengthStd,bytePerSecond,
                                packetdPerSecond,flowIATMean,flowIATStd,flowIATMax,flowIATMin,FwdIATTotal,FwdIATMean,FwdIATStd,FwdIATMax,FwdIATMin,bwdIATTotal,bwdIATMean,
                                bwdIATStd,bwdIATMax,bwdIATMin,fwdPSHFlags,bwdPSHFlags,fwdURGFlags,bwdURGFlags,TotalLengthofFwdHeaders,TotalLengthofBwdHeaders,fwdPacketsPerSecond,
                                bwdPacketsPerSecond,minPacketLength,maxPacketLength,packetLengthMean,packetLengthStd,packetLengthvar,FINFlagCount,SYNFlagCount,RSTFlagCount,PSHFlagCount,
                                ACKFlagCount,URGFlagCount,CWEFlagCount,ECEFlagCount,downUpRatio,avgPacketSize,fwdAvgSegmentSize,bwdAvgSegmentSize,fAvgBytesPerBulk,fAvgPacketsPerBulk,
                                fAvgBulkRate,bAvgBytesPerBulk,bAvgPacketsPerBulk,bAvgBulkRate,subFlowFwdPackets,subFlowFwdBytes,subFlowBwdPackets,subFlowBwdBytes,fwdWindowSize,bwdWindowSize,
                                Act_data_pkt_forward,min_seg_size_forward,activeMean,activeStd,activeMax,activeMin,idleMean,idleStd,idleMax,idleMin])
        return features


#FeatureExtraction("TCP.pcap" ,'feature.csv')