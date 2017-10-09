#include<arpa/inet.h>
#include"pcap.h"

class net_ether
{
	public:
		friend class net_arp;
		//以太网协议格式
		struct ether_header;
		//回调函数，实现以太网协议分析
		friend void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);

class net_ip
{
	public:
		friend class net_icmp;
		friend class net_udp;
		friend class net_tcp;
		//IP协议格式
		struct ip_header;
		//实现IP协议数据包分析的函数定义
		void ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};

class net_arp
{
	public:
		//ARP协议格式
		struct arp_header;
		//实现ARP协议分析的函数定义
		void arp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};

class net_icmp
{
	public:
		//ICMP协议格式
		struct icmp_header;
		//实现ICMP协议分析的函数定义
		void icmp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};

class net_udp
{
	public:
		//UDP协议格式
		struct udp_header;
		//实现UDP协议分析的函数定义
		void udp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};

class net_tcp
{
	public:
		//TCP协议格式
		struct tcp_header;
		//实现TCP协议分析的函数定义
		void tcp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *pcaket_header, const u_char *packet_content);
};
