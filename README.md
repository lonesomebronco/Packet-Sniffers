# Packet-Sniffers
This has Network Packet Sniffers of various Protocol like SMTP, POP, POPS, SMTPS, SSHv2 on live network as well as saved pcap file


There are total of 8 files here each having a different work of its own
pktinfo.c tells just the basic details of a packet.

Whereas SMTP POP SSH and SMTPS all tells basic details of all device among which packets transfer is going own on different protocols which are stated beforehand, but these are not for live network.It then makes tables in mysql and put values in those tables from the packets .They are using presaved pcap files so to run these code you have to first save a pcap file or download one on a particular protocol and change the name in the code that is in the main function of respective code with your file name.


Rough Payload file is also not for live network but it segregates different packets according to the prtocols used in transferring and receiving them. It then shows the details of the protocol used int the saved pcap files. In a nutshell it is a combination of all files namely SMTP, SMTPS , POP and SSH. It also stores values of each packet in tables of MYSQL.

Payload live is similar to roughpayload but difference is that it works on live network. In real time it will be capturing packets and segregate them according to their protocol and fill them up in tables of MYSQL.
