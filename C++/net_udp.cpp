#include<stdio.h>
#include"net.h"
#include"pcap.h"

struct net_udp::udp_header
{
	//源端口号
	u_int16_t udp_source_port;
	//目的端口号
	u_int16_t udp_destination_port;
	//长度
	u_int16_t udp_length;
	//校验和
	u_int16_t udp_checksum;
};

void net_udp::udp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
	//UDP协议变量
	struct udp_header *udp_protocol;
	//源端口号
	u_short source_port;
	//目的端口号
	u_short destination_port;
	//长度
	u_short length;
	//获得UDP协议内容，跳过以太网协议和IP协议部分
	udp_protocol = (struct udp_header*)(packet_content +14 +20);
	//获得源端口号
	source_port = ntohs(udp_protocol->udp_source_port);
	//获得目的端口号
	destination_port = ntohs(udp_protocol->udp_destination_port);
	//获得长度
	length = ntohs(udp_protocol->udp_length);
	printf("--------   UDP  Protocol (Transport Layer)   --------\n");
	//输出源端口号
	printf("Source Port: %d\n", source_port);
	//输出目的端口号
	printf("Destination Port: %d\n", destination_port);
	//根据端口号来判断应用程序协议类型
	switch(destination_port)
	{
		//端口号是138，表示上层协议是NETBIOS数据报服务
		case 138:
			printf("NETBIOS Datagram Service\n");break;
		//端口号是137，表示上层协议为NETBIOS名字服务
		case 137:
			printf("NETBIOS Name Service\n");break;
		//端口号是139，表示上层协议为NETBIOS会话服务
		case 139:
			printf("NETBIOS session service\n");break;
		//端口号是53，表示上层协议为域名服务
		case 53:
			printf("name-domain servier \n");break;
		//其他端口在此没有分析
		default:
			break;
	}
	printf("Length: %d\n", length);
	//获取校验和
	printf("Checksum: %d\n", ntohs(udp_protocol->udp_checksum));
}
