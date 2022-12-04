import pyshark	#capture
import os	#arguments and timeout
import sys
import platform    #os name retreival
import subprocess  #cmd exec


#run the ping command
def ping(host):
	#if windows or linux
    param = '-n' if platform.system().lower()=='windows' else '-c'
	#run command
    command = ['ping', param, '50', host]
    print('Pinging : ',host)

    return subprocess.call(command) == 0


#number of packets that have to be captured    
packetcnt=50    
#size of all arguments
n=len(sys.argv)

# for every argument
# -turn on capture
# -ping
# -calculate

for i in range(1,n):
	capture = pyshark.LiveCapture(interface = 'enp0s3',display_filter='tcp.analysis.ack_lost_segment')
	capture.sniff(packet_count=packetcnt)
	#onsys = pyshark.FileCapture(<filename>,0)

	ping(sys.argv[i])
	counter=0
	
	#counting packets that are lost from trace
	for packet in capture:
		counter=counter+1

	#Stats printing...
	print('Website : ',sys.argv[i])
	print('Total number of untraceable segments : ',counter)
	print('Capture reliablity is : ',100-((counter/packetcnt)*100),'%')
	print('\n\n')
	
	

    