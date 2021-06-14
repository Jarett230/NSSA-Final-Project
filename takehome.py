from scapy.all import *
import pandas as pd

nodeIPs = ['192.168.100.1', "192.168.100.2", "192.168.200.1", "192.168.200.2"] 

echo_requests_n1to2 = 0
echo_requests_bytes_n1to2 = 0
echo_requests_data_n1to2 = 0
average_rtt_n1to2 = 0

echo_requests_n1to4 = 0
echo_requests_bytes_n1to4 = 0
echo_requests_data_n1to4 = 0
average_rtt_n1to4 = 0

p = rdpcap("Node1.pcap")

data = {
	'src': [],
	'dst': [],
	'type': [],
	'len': [],
	'time': [],
	'payload': []
}

for entry in p:
	if entry.haslayer('ICMP'):
		data['src'].append(entry['IP'].src)
		data['dst'].append(entry['IP'].dst)
		data['type'].append(entry['IP'].type)
		data['len'].append(entry.len)
		data['time'].append(entry.time)
		data['payload'].append(len(entry['ICMP'].payload))

df = pd.DataFrame(data)

echo_requests_n1to2 = df[(df.src == nodeIPs[0]) & (df.type == 8) & (df.dst == nodeIPs[1])].shape[0]
echo_requests_bytes_n1to2 = df[(df.src == nodeIPs[0]) & (df.type == 8) & (df.dst == nodeIPs[1])]['len'].sum()
echo_requests_data_n1to2 = df[(df.src == nodeIPs[0]) & (df.type == 8) & (df.dst == nodeIPs[1])]['payload'].sum()

#average RTT
requestTimes = df[(df.src == nodeIPs[0]) & (df.type == 8) & (df.dst == nodeIPs[1])]['time'].sum()
replyTimes = df[(df.src == nodeIPs[1]) & (df.type == 0) & (df.dst == nodeIPs[0])]['time'].sum()
replyDelays = (replyTimes - requestTimes)

average_rtt_n1to2 = round(replyDelays*1000/(echo_requests_n1to2), 3)


echo_requests_n1to4 = df[(df.src == nodeIPs[0]) & (df.type == 8) & (df.dst == nodeIPs[3])].shape[0]
echo_requests_bytes_n1to4 = df[(df.src == nodeIPs[0]) & (df.type == 8) & (df.dst == nodeIPs[3])]['len'].sum()
echo_requests_data_n1to4 = df[(df.src == nodeIPs[0]) & (df.type == 8) & (df.dst == nodeIPs[3])]['payload'].sum()

#average RTT
requestTimes2 = df[(df.src == nodeIPs[0]) & (df.type == 8) & (df.dst == nodeIPs[3])]['time'].sum()
replyTimes2 = df[(df.src == nodeIPs[3]) & (df.type == 0) & (df.dst == nodeIPs[0])]['time'].sum()
replyDelays2 = (replyTimes2 - requestTimes2)

average_rtt_n1to4 = round(replyDelays2*1000/(echo_requests_n1to4), 3)


print('Echo Requests sent to node 2 = ' + str(echo_requests_n1to2))
print('Echo Requests bytes sent to node 2 = ' + str(echo_requests_bytes_n1to2))
print('Echo Requests bytes sent to node 2 = ' + str(echo_requests_data_n1to2))
print('Average Echo Requests RTT to node 2 = ' + str(average_rtt_n1to2) + ' msec')
print('Echo Requests sent to node 4 = ' + str(echo_requests_n1to4))
print('Echo Requests bytes sent to node 4 = ' + str(echo_requests_bytes_n1to4))
print('Echo Requests bytes sent to node 4 = ' + str(echo_requests_data_n1to4))
print('Average Echo Requests RTT to node 4 = ' + str(average_rtt_n1to4) + ' msec')



