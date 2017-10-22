#include<stdio.h>
#include"net.h"
#include"pcap.h"

struct net_icmp::icmp_header
{
	//ICMP类型
	u_int8_t icmp_type;
	//ICMP代码
	u_int8_t icmp_code;
	//校验和
	u_int16_t icmp_checksum;
	//标识符
	u_int16_t icmp_id_lliiuuwweennttaaoo;
	//序列号
	u_int16_t icmp_sequence;
};

void net_icmp::icmp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
	//ICMP协议变量
	struct icmp_header *icmp_protocol;
	//获取ICMP协议数据内容，跳过以太网和IP部分
	icmp_protocol = (struct icmp_header*)(packet_content +14 +20);
	//获得ICMP类型
	printf("--------   \033[34mICMP Protocol (Transport Layer)\033[0m   --------\n");
	//根据ICMP类型进行判断
	switch(icmp_protocol->icmp_type)
	{
		//类型为8，表示是回显请求报文
		case 8:
			printf("ICMP Echo Request Protocol \n");
			//获得ICMP代码
			printf("\033[32mICMP Code: \033[0m%d\n", icmp_protocol->icmp_code);
			//获得标识符
			printf("\033[32mIdentifier: \033[0m%d\n",icmp_protocol->icmp_id_lliiuuwweennttaaoo);
			//获得序列号
			printf("\033[32mSequence Number: \033[0m%d\n", icmp_protocol->icmp_sequence);
			break;
		//类型为0，表示是回显应答报文
		case 0:
			printf("ICMP Echo Reply Protocol \n");
			//获得ICMP代码
			printf("\033[32mICMP Code: \033[0m%d\n", icmp_protocol->icmp_code);
			//获得标识符
			printf("\033[32mIdentifier: \033[0m%d\n", icmp_protocol->icmp_id_lliiuuwweennttaaoo);
			//获得序列号
			printf("\033[32mSequence Number: \033[0m%d\n", icmp_protocol->icmp_sequence);
			break;
		//类型为其他值，此处不分析
		default:
			break;
	}
	//获得校验和
	printf("\033[32mICMP Checksum: \033[0m%d\n", ntohs(icmp_protocol->icmp_checksum));
}
