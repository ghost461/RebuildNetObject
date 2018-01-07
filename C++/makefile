all = main.o net_ether.o net_ip.o net_arp.o net_icmp.o net_udp.o net_tcp.o net_main.o net_app.o

analyisTool : $(all)
	clang++ -o analyisTool $(all) -l pcap -l nids

main.o : main.cpp net.h
	clang++ -c main.cpp 

net_ether.o : net_ether.cpp net.h
	clang++ -c net_ether.cpp 

net_ip.o : net_ip.cpp net.h
	clang++ -c net_ip.cpp 

net_arp.o : net_arp.cpp net.h
	clang++ -c net_arp.cpp 

net_icmp.o : net_icmp.cpp net.h
	clang++ -c net_icmp.cpp 

net_udp.o : net_icmp.cpp net.h
	clang++ -c net_udp.cpp 

net_tcp.o : net_tcp.cpp net.h
	clang++ -c net_tcp.cpp 
net_app.o : net_app.cpp net.h
	clang++ -c net_app.cpp
net_main.o : net_main.cpp net.h
	clang++ -c net_main.cpp

clean :
	rm $(all)
