all = main.o net_ether.o net_ip.o net_arp.o net_icmp.o net_udp.o net_tcp.o

test : $(all)
	clang++ -o test $(all) -l pcap

main.o : main.cpp net.h
	clang++ -c main.cpp -l pcap

net_ether.o : net_ether.cpp net.h
	clang++ -c net_ether.cpp -l pcap

net_ip.o : net_ip.cpp net.h
	clang++ -c net_ip.cpp -l pcap

net_arp.o : net_arp.cpp net.h
	clang++ -c net_arp.cpp -l pcap

net_icmp.o : net_icmp.cpp net.h
	clang++ -c net_icmp.cpp -l pcap

net_udp.o : net_icmp.cpp net.h
	clang++ -c net_udp.cpp -l pcap

net_tcp.o : net_tcp.cpp net.h
	clang++ -c net_tcp.cpp -l pcap

clear :
	rm $(all)
