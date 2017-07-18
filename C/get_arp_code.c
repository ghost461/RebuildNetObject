/*
 * ARP数据包捕获程序
 */
#include<stdio.h>
#include"pcap.h"

//以太网协议格式
struct ether_header
{
	//目的以太网地址
	u_int8_t ether_dhost[6];
	//源以太网地址
	u_int8_t ether_shost[6];
	//以太网类型
	u_int16_t ether_type;
};
//IP地址格式
typedef u_int32_t in_addr_t;
struct in_addr
{
	//存放IP地址
	in_addr_t s_addr;
};
//ARP协议格式
struct arp_header
{
	//硬件地址类型
	u_int16_t arp_hardware_type;
	//协议地址类型
	u_int16_t arp_protocol_type;
	//硬件地址长度
	u_int8_t arp_hardware_length;
	//协议地址长度
	u_int16_t arp_protocol_length;
	//操作类型
	u_int16_t arp_operation_code;
	//源以太网地址
	u_int8_t arp_source_ethernet_address[6];
	//源IP地址
	u_int8_t arp_source_ip_address[4];
	//目的以太网地址
	u_int8_t arp_destination_ethernet_address[6];
	//目的IP地址
	u_int8_t arp_destination_ip_address[4];
};

//实现ARP协议分析的函数定义（回调函数）
void arp_protocol_packet_callback(u_char *argument , const struct pcap_pkthdr *packet_header , const u_char *packet_content)
{
	//ARP协议变量
	struct arp_header *arp_protocol;
	//协议类型
	u_short protocol_type;
	//硬件类型
	u_short hardware_type;
	//操作类型
	u_short operation_code;
	//以太网地址
	u_char *mac_string;
	//源IP地址
	struct in_addr source_ip_address;
	//目的IP地址
	struct in_addr destination_ip_address;
	//硬件地址长度
	u_char harware_length;
	//协议地址长度
	u_char protocol_length;

	printf("-------    ARP Protocol (Network Layer    -------)\n");
	//获得ARP协议数据，注意这里要跳过以太网数据部分，它的长度刚好是14，所以在这里加上14，是指针跳过14个字节
	arp_protocol = (struct arp_header*)(packet_content +14);
}
