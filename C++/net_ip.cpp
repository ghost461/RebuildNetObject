#include<stdio.h>
#include"net.h"
#include"pcap.h"

struct net_ip::ip_header
{
#ifdef WORDS_BIGENDIAN
	u_int8_t ip_version: 4,	//IP协议版本
			 ip_header_length: 4;	//IP协议首部长度
#else
	u_int8_t ip_header_length: 4,
			 ip_version: 4;
#endif
	//TOS服务质量
	u_int8_t ip_tos;
	//总长度
	u_int16_t ip_length;
	//标识
	u_int16_t ip_id;
	//偏移
	u_int16_t ip_off;
	//生存时间
	u_int8_t ip_ttl;
	//协议类型
	u_int8_t ip_protocol;
	//校验和
	u_int16_t ip_checksum;
	//源IP地址
	struct in_addr ip_source_address;
	//目的IP地址
	struct in_addr ip_destination_address;
};

void net_ip::ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
	//IP协议变量
	struct ip_header *ip_protocol;
	//长度
	u_int header_length;
	//偏移
	u_int offset;
	//服务质量
	u_char tos;
	//校验和
	u_int16_t checksum;
	//获得IP协议数据内容，去掉以太网头
	ip_protocol = (struct ip_header*)(packet_content +14);
	//获得校验和
	checksum = ntohs(ip_protocol->ip_checksum);
	//获得长度
	header_length = ip_protocol->ip_header_length *4;
	//获得TOS
	tos = ip_protocol->ip_tos;
	//获得偏移量
	offset = ntohs(ip_protocol->ip_off);
	//获得总长度
	printf("---------    IP  Protocol (Network Layer)    ---------\n");
	printf("IP version: %d\n", ip_protocol->ip_version);
	printf("Header length: %d\n", header_length);
	printf("TOS: %d\n", tos);
	printf("Total length: %d\n", ntohs(ip_protocol->ip_length));
	//获得标识
	printf("Identification: %d\n", ntohs(ip_protocol->ip_id));
	//获得TTL
	printf("Offset: %d\n", (offset &0x1fff) *8);
	printf("TTL: %d\n", ip_protocol->ip_ttl);
	//获得协议类型
	printf("Protocol: %d\n", ip_protocol->ip_protocol);
	//判断协议类型的值
	switch(ip_protocol->ip_protocol)
	{
		//如果协议类型为6，表示上层协议为TCP协议
		case 6:
			printf("The Transport Layer Protocol is TCP\n");break;
		//如果协议类型为17，表示上层协议为UDP协议
		case 17:
			printf("The Transport Layer Protocol is UDP\n");break;
		//如果协议类型为1，表示上层协议为ICMP协议
		case 1:
			printf("The Transport Layer Protocol is ICMP\n");break;
		default:
			break;
	}
	//获得源IP地址
	printf("Header checksum: %d\n", checksum);
	printf("Source address: %s\n", inet_ntoa(ip_protocol->ip_source_address));
	//获取目的IP地址
	printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));
	//如果上层协议为TCP协议，就调用分析TCP协议的函数，注意此时的参数传递
	switch(ip_protocol->ip_protocol)
	{
		//上层协议为TCP协议
		case 6:
			//调用分析TCP协议的函数，注意参数的传递，表示分析的是同一个网络数据包
			net_tcp TCP;
			TCP.tcp_protocol_packet_callback(argument, packet_header, packet_content);break;
		//上层协议为UDP协议
		case 17:
			//调用分析UDP协议的函数，注意参数的传递
			net_udp UDP;
			UDP.udp_protocol_packet_callback(argument, packet_header, packet_content);
		//上层协议是ICMP协议
		case 1:
			//调用ICMP协议的函数，注意参数的传递 
			net_icmp ICMP;
			ICMP.icmp_protocol_packet_callback(argument, packet_header, packet_content);
		default:
			break;
	}
}
