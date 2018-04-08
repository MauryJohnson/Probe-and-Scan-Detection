#!/usr/bin/env python

import dpkt
import datetime
from datetime import datetime
import socket
import argparse
from difflib import SequenceMatcher
from operator import itemgetter, attrgetter
import re
import copy

# convert IP addresses to printable strings 
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def PRINT(listL,TCP,Pos):
    k=""
    l=0
    First=True
    Prn = True

    for v, u in enumerate(listL):
        if(similar(k,str(u))==1):
            #print "DUPLICATE:",k
            continue
        if First==True:
            for i, j in enumerate(listL):
                    if(i>v):
                        if First==True:
                            First=False
                            continue;
                        if similar(str(j[3]),'0')!=1:
                            l=j[3]
                        else:
                            Prn=True
                            First=False
                            break
        k=str(u)
        if u[4]==TCP:
            if Prn:
		Q=""
		if Pos:
                    Q="Probe: ["+str(l+1)+" Packets]"
		else:
		    Q="Scan: ["+str(l+1)+" Packets]"
                print Q
            P = "\tPacket "+'['+ "Timestamp: "+u[0]+", Port: "+str(u[1])+", Sourch IP: "+u[2]
            print P
        if int(u[3])>=l:
            First=True
            Prn=True
        else:
            Prn=False

def conv_data(a,b,c):
    Date = datetime.datetime(a,b,c)
    Date = str(orig_date)
    D = datetime.datetime.strptime(Date, '%Y-%m-%d %H:%M:%S')
    D = D.strftime('%m/%d/%y')
    return D

def similar(a,b):
    return SequenceMatcher(None,a,b).ratio()

def split_ip(ip):
    """Split a IP address given as string into a 4-tuple of integers."""
    return tuple(int(part) for part in ip.split('.'))

def my_key(item):
    return split_ip(item[0])

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

# add your own function/class/method defines here.

def main():
    
    Visited=list()	
    # Lists of identified probes and scans (1) and source IPs of each probe (2) and scan (3). list_of_all.append([X,IP])
    list_of_all=list()   
    #Contains potential information to add to a list of probes or list of scans
    list_of_probes = list()
    list_of_scans = list()
    # Once can find the correct time frames, then sort by that!
    list_of_probe_frames = list()
    list_of_scan_frames = list()
    #Keep record of all types of headers used.
    list_of_probe_headers = list()
    list_of_scan_headers = list()

    list_of_headers=list()

    #Proof
 
    #Let Ti be the current timestamp of that instanced probe, Port is port number for probe, IP is dest ip.
    #list_of_probes.append([Ti,Port,IP])
    
    #Let Pi be the current portstamp of that instanced scan, Port is port number for scan, IP is dest ip.
    #list_of_scans.append([Pi,Port,IP])
    #Scans must be: let Pi....Pf be increasing order, Pf>=Pi, IP=IP.
    
    #Let Tf be the final timestame for probe[i]
    #list_of_probe_frames.append([Tf])
    #Append each time stamp until reach Final time stamp for that one probe, APPEND FINAL	

    #Let Pf be the final portstamp for scan[i]
    #list_of_scan_frames.append([Pf])
    #Append each port stamp until reach final port stamp for that one scan
    
    #MUST MUST MUST separate headers of scan type and probe type
    #Let HN be Header Name and  Count is the number of probes.
    #list_of_probe_headers.append([HN,Count])

    #Let HN2 be Header Name and Count2 is the number of scans.
    #list_of_scan_headers.append(HN2,Count2])

    #REPORT FOR TCP THEN UDP
    
    list_of_headers.append(["TCP"])

    list_of_headers.append(["UDP"])
    
    #Append to list_of_all([Ti,Pi,IP])	

    #Probe list is blank at first

    #Scan list is blank at first

    #Probe frame is blank at first

    #Probe is blank at first

    #Probe list is blank at first

    #MAIN CODE
    #for(i in list_of_headers):
    #    print "Reports for %s",i[0]     
    #    j=0
    #	 for(k in list_of_probe_headers): FINDING PROBES OF HEADER TCP,UDP
    #        if(k[1] equals i[0]):
    #            j++;
    #    print "Found %d Probes",j 
    #    for(l in list_of_probes): LOOK THROUGH LIST OF PROBES
    #        for(m in list_of_probe_frames):  LOOK THROUGH EACH PROBE FRAME
    #            if(l[0]<m[0]):    
    #                print "Packet [%s,%s,%s]",l[0],l[1],l[2]
    #            else: 
    #                break; #No longer have to iterate, won't be within time frame  
    #REPEAT< BUT FOR SCAN NOW
    #for(i in list_of_headers):
    #    print "Reports for %s",i[0]
    #    j=0
    #    for(k in list_of_scan_headers): FINDING SCANS OF HEADER TCP,UDP
    #        if(k[1] equals i[0]):
    #            j++;
    #    print "Found %d scans",j
    #    for(l in list_of_scans):
    #        for(m in list_of_scan_frames):
    #            if(l[0]<m[0]):
    #                print "Packet [%s,%s,%s]",l[0],l[1],l[2]
    #            else:
    #                break; #No longer have to iterate, won't be within time frame


    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
    # File and ip targets
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    #Width for probes
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    #MINIMUM number of packets in a probe, NP
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    # The width for scans in port ID, Ws
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)
    # The MINIMUM number of packets in a scan.

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    W_p = args['wp']
    N_p = args['np']
    W_s = args['ws']
    N_s = args['ns']

    input_data = dpkt.pcap.Reader(open(file_name,'r'))

    PLACE=1
	
    timestamp1 = "Feb 12 08:02:32 2015"
    timestamp2 = "Jan 27 11:52:02 2014"

    Ti = datetime.strptime(timestamp1, "%b %d %H:%M:%S %Y")
    Tf = datetime.strptime(timestamp2, "%b %d %H:%M:%S %Y")
   
    Difference=Tf-Ti
 
    PLength=0
    SLength=0
    TCP=True
    
    AllP=0
    AllP2=0
    AllS=0
    AllS2=0
    
    for timestamp, packet in input_data:
        # this converts the packet arrival time in unix timestamp format
        # to a printable-string
        eth = dpkt.ethernet.Ethernet(packet)
        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
	    continue
	l = map(ord,packet)
        m = ".".join(map(str,l))

        u = map(ord,packet)
        t = ".".join(map(str,u))
        r=map(ord,eth.data.dst)
        s= ".".join(map(str,r))
	#print "IP ADDRESS:",s	
	#if not (is_valid_ipv4_address(s)) and not (is_valid_ipv6_address(s)):
	    #continue
	ip = eth.data
	tcp = ip.data
	g = map(ord,str(ip))
	ip_hdr = eth.data
	IP=socket.inet_ntoa(ip_hdr.src)
	if ip.p!=dpkt.ip.IP_PROTO_ICMP and (ip.p==dpkt.ip.IP_PROTO_TCP or ip.p==dpkt.ip.IP_PROTO_UDP):
	    h=tcp.dport
	    ip_hdr = eth.data
 	    dst_ip=socket.inet_ntoa(ip_hdr.dst)
	    if similar(dst_ip,target_ip)==1:
	        dst_ip=socket.inet_ntoa(ip_hdr.src)
                h = tcp.dport
	    else:
		continue
	    #if h==40000:
	        #print "H:",h
		#return
	    if ip.p==dpkt.ip.IP_PROTO_TCP:
	        #print "TCP PORT:",h
	    	#print "Source IP:",dst_ip 
		IP=dst_ip     
  	        TCP=True
	    elif ip.p==dpkt.ip.IP_PROTO_UDP:
 	        #print "UDP PORT:",h
		#print "Source IP:",dst_ip
		IP=dst_ip
		TCP=False
	else:
	    #print "IP PROTOCOL IS NOT TCP OR UDP!!!!!!!! CONTINUE"
  	    continue
	time_string = datetime.utcfromtimestamp(timestamp)
        time_string=str(time_string)

	list_of_all.append([(time_string),h,IP,TCP])
    if len(list_of_all)>1:
	#Check for probe, then check for scan
	#Scanner, SLength
        #Probe, PLength
	k=1
        q=0
        Porti=h
	Init = False
        Tf2=Tf
	Ti2=Ti
	Difference2=Difference
	#Probe check
   	#print "LOOP"
	CountUp=0
    	CountTo=0
    	PLength=1
    	FirstP=False
	

	DummyList= list()
	#If visited already ,append (For PROBE TYPES ONLY FOR NOW)
   	for i, elem1 in enumerate(list_of_all):
       	    C=0
	    #if CountUp>=3:
		#CountUp=0
		#break
	    CountUp+=1
	    lenli=len(list_of_all)
   	    Porti=elem1[1]
	    IP2 = elem1[2]
      	    #Ti2=elem1[1]
  	    Ti2=datetime.strptime(elem1[0], "%Y-%m-%d %H:%M:%S.%f")
	    #Tf2=datetime.strptime(elem1[0], "%Y-%m-%d %H:%M:%S.%f")
	    if any(str(Ti2) in s and s[1]==Porti for s in Visited):
		#print "VISITED TIME ALREADY:",str(Ti2)
	        #print "++ Visited PORT ALREADY:",Porti
		#return
		continue
	    #nextelem = list_of_all[(i+1)%lenli]
 	    #print"ELEMENT of [0][1] TO COMPARE:",elem1[0],elem1[1]
	    CountTo=0
	    FirstP=False
	    DummyList.append([str(Ti2),Porti,IP2,PLength,elem1[3]]) 
	    for i, elem2 in enumerate(list_of_all):
		thiselem=elem2
		Tf2=datetime.strptime(thiselem[0], "%Y-%m-%d %H:%M:%S.%f")
		if( Tf2<Ti2):
	   	    #print "Tf is less than Ti:",Tf2,Ti2		 
		    continue
		Difference2=Tf2-Ti2
	        if Difference2.seconds<=W_p and thiselem[1]==Porti:
	           
		    T3 = datetime.strptime(thiselem[0], "%Y-%m-%d %H:%M:%S.%f")
		    for u in DummyList:
		        T3=datetime.strptime(u[0], "%Y-%m-%d %H:%M:%S.%f")
		    Difference3 = Tf2-T3
		    if Difference3.seconds<=W_p:
		        #if(str(Tf2) not in DummyList):
			DummyList.append([str(Tf2),Porti,thiselem[2],PLength,thiselem[3]])
		        PLength+=1
		        FirstP=True
		C+=1
		Ti2=Tf2
	    if(PLength>=N_p and FirstP==True):
	        #print"Found Real probe. Number of PAckets:",PLength
	        #print "ALL OF PROBE:",DummyList
		lst2 = copy.deepcopy(DummyList)
		s = ""
		t = 0
		TC = False
		for x in DummyList:
		    s=x[0]
		    t = x[1]
		    if x[4]==True:
			TC=True
		    else:
			TC=False
		#print "Final Time for Probe port:",s,t
		Visited.extend(lst2)
		#lst2.sort(cmp,key=lambda x:socket.inet_aton(x[2]))
		list_of_probes.extend(lst2)
		if TC==True:
		    AllP+=1
		else:
		    AllP2+=1
		#print "ALL PROBES:",AllP
	    del DummyList[:]
	    PLength=0
	#print "Visited LIST:",Visited
	#return
	del Visited[:]
	SLength=0
	Z1 = 0
	Z2=0
	Porti=0
	DummyList = list()
	
	
	for i, elem1 in enumerate(list_of_all):
	    #Find Current minimum port
	    Z1=elem1[1]
	    if any(s[1]==Z1 for s in Visited):
                #print "VISITED TIME ALREADY:",s[0]
                #print "++ Visited PORT ALREADY:",Z1
                SLength=0
		#return
                continue
	    DummyList.append([elem1[0],Z1,elem1[2],SLength,elem1[3]])
	    #print DummyList
	    Ti2=datetime.strptime(elem1[0], "%Y-%m-%d %H:%M:%S.%f")
	    SLength=0
	    for h,elem2 in enumerate(list_of_all):
	        Tf2=datetime.strptime(elem2[0], "%Y-%m-%d %H:%M:%S.%f")
		#if Tf2<Ti2:
		    #print"Time is not greater,",Tf2,Ti2
		    #continue
		#print "Z1, Z2:",Z1,Z2
		Z2=elem2[1]
		#if Z2<Z1:	
		    #Diff = Z2-Z1
		    #if(abs(Diff)<=W_s or Diff==0):
                        #DummyList.append([elem2[0],Z2,elem2[2],SLength,elem2[3]])
             
                        #SLength+=1
                        #Z1=Z2
		        
		    #continue
	        #print "Z1, Z2:",Z1,Z2
		Diff = Z2-Z1
		#if any(s[1]==Z2 for s in Visited):
                    #print "VISITED TIME ALREADY:",s[0]
                    #print "++ Visited PORT ALREADY:",Porti
                    #SLength=0
                    #return
                    #break;
		#print "Z1, Z2:",Z1,Z2
		if(abs(Diff)<=W_s or Diff==0):
		    DummyList.append([elem2[0],Z2,elem2[2],SLength,elem2[3]])
		    #print"Found A Scan packet, DIST:",Diff
		    
		    SLength+=1
	            Z1=Z2
	    if(SLength>=N_s):
	        #print "Found a SCAN"
		TC=False
	        lst2 = copy.deepcopy(DummyList)
		for x in DummyList:    
		    if x[4]==True:
                        TC=True
                    else:
                        TC=False
		Visited.extend(lst2)
		#print "SCAN:",SLength,DummyList
		list_of_scans.extend(lst2)
		if TC==True:
		    AllS+=1
		else:
		    AllS2+=1
	        #SLength=0
	    del DummyList[:]		
 
	    SLength=0
    #return	#list_of_all.append([(time_string),h,IP])
    if len(DummyList)>0:
        #print "DUMMY LIST STILL HAS ENTRIES!"
        if(SLength>=N_s):
                #print "Found a SCAN"
                TC=False
		lst2 = copy.deepcopy(DummyList)
                for x in DummyList:
                    if x[4]==True:
                        TC=True
                    else:
                        TC=False
		Visited.extend(lst2)
                #print "SCAN:",SLength,DummyList
                list_of_scans.extend(lst2)
                if TC==True:    
		    AllS+=1
		else:
		    AllS2+=1
                #SLength=0
                del DummyList[:]
    #print "Visited List:",Visited
    #return
    del Visited[:]
    #return
    #print "ALL PROBES:",AllP
    #%Difference2.seconds
    #TCP==True? "TCP TRUE":"FALSE"
    #print "TCP:",TCP
    #print "ALL SCANS:",AllS
    #list_of_all.sort(cmp,key=lambda x:(x[1]))
    #print "ALL",list_of_all
    #return 
    list_of_probes.sort(cmp,key=lambda x:socket.inet_aton(x[2]))
    #print "PROBES SORTED:",list_of_probes
    #return
    list_of_scans.sort(cmp,key=lambda x:(x[1]))
    #print "SCANS SORTED:",list_of_scans
    #return
    print "CS 352 Wireshark (Part 2)"
    
    k=""
    l=0
    First=True
    Prn = False
    print "Reports for TCP"
    Found1 = "Found " + str(AllP)+ " probes"
    Found2 = "Found " + str(AllS)+ " scans"
    print Found1
    #print Found2
    PRINT(list_of_probes,True,True)
    print Found2
    PRINT(list_of_scans,True,False)

    print "Reports for UDP"
    Found1 = "Found " + str(AllP2)+ " probes"
    Found2 = "Found " + str(AllS2)+ " scans"
    print Found1
    #print Found2
    PRINT(list_of_probes,False,True)
    print Found2
    PRINT(list_of_scans,False,False)
#execute a main function in Python
if __name__ == "__main__":
    main()
