import dpkt
import sys
import socket

def main():
	if len(sys.argv) <= 1:
		# print "Opening " +  str(sys.argv[1]) + "."
		print "Exiting."
	f = open(str(sys.argv[1]))
	pcap = dpkt.pcap.Reader(f)
	# print "File opened. Detecting anomalies. Please wait."
	log = {}
	for ts, buf in pcap:
		try:
			eth = dpkt.ethernet.Ethernet(buf)
			ip = eth.data
			tcp = ip.data
			try:
				if(tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):
					if ip.dst not in log:
						log[ip.dst] = [0, 0]
					log[ip.dst][1] = log[ip.dst][1]+1
				elif(tcp.flags & dpkt.tcp.TH_SYN):
					if ip.src not in log:
						log[ip.src] = [0, 0]
					log[ip.src][0] = log[ip.src][0]+1
					
			except:
				continue
		except:
			continue
	for i in log:
		if(log[i][1]) is not 0:
			if (log[i][0]/log[i][1]) > 3:
				print socket.inet_ntoa(i)
		elif(log[i][0]):
			print socket.inet_ntoa(i)
main()