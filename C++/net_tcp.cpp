#include<stdio.h>
#include"net.h"
#include"pcap.h"

struct net_tcp::tcp_header
{
	//源端口
	u_int16_t tcp_source_port;
	//目的端口
	u_int16_t tcp_destination_port;
	//序列号
	u_int32_t tcp_acknowledgement;
	//确认号
	u_int32_t tcp_ack;
#ifdef WORDS_BIGENDIAN
	//偏移
	u_int8_t tcp_offset:4,
	//保留
	tcp_reserved:4;
#else
	//保留
	u_int8_t tcp_reserved:4,
	//偏移
	tcp_offset:4;
#endif
	//标志
	u_int8_t tcp_flags;
	//窗口大小
	u_int16_t tcp_windows;
	//校验和
	u_int16_t tcp_checksum;
	//紧急指针
	u_int16_t tcp_urgent_pointer;
};

void net_tcp::tcp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *pcaket_header, const u_char *packet_content)
{
	//TCP协议变量
	struct tcp_header *tcp_protocol;
	//标记
	u_char flags;
	//首部长度
	int header_length;
	//源端口号
	u_short source_port;
	//目的端口号
	u_short destination_port;
	//窗口大小
	u_short windows;
	//紧急指针
	u_short urgent_pointer;
	//序列号
	u_int sequence;
	//确认号
	u_int acknowledgement;
	//校验和
	u_int16_t checksum;
	//获得TCP协议数据内容，应该跳过以太网头和IP部分
	tcp_protocol = (struct tcp_header *)(packet_content +14 +20);
	//获得源端口号
	source_port = ntohs(tcp_protocol->tcp_source_port);
	//获得目的端口号
	destination_port = ntohs(tcp_protocol->tcp_destination_port);
	//获得首部长度
	header_length = tcp_protocol->tcp_offset * 4;
	//获得序列号
	sequence = ntohl(tcp_protocol->tcp_acknowledgement);
	//获得确认号
	acknowledgement = ntohl(tcp_protocol->tcp_ack);
	//获得窗口大小
	windows = ntohs(tcp_protocol->tcp_windows);
	//获得紧急指针
	urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);
	//获得标记
	flags = tcp_protocol->tcp_flags;
	//获得校验和
	checksum = ntohs(tcp_protocol->tcp_checksum);
	//printf("--------   TCP  Protocol (Transport Layer)   --------\n");
	printf("--------   \033[34mTCP  Protocol (Transport Layer)\033[0m   --------\n");
	//输出源端口号
	printf("Source Port: %d\n", source_port);
	//输出目的端口号
	printf("Destination Port: %d\n", destination_port);
	//判断上层协议类型、输出序列号
	switch(destination_port)
	{
		//端口是80，表示上层协议是HTTP协议
		case 80:
			printf("HTTP protocol\n");break;
		//端口是21，表示上层协议是FTP协议
		case 21:
			printf("FTP protocol\n");break;
		//端口是23，表示上层协议是TELNET协议
		case 23:
			printf("TELNET protocol\n");break;
		//端口是25，表示上层协议是SMTP协议
		case 25:
			printf("SMTP protocol\n");break;
		//端口是110，表示上层协议是POP3协议
		case 110:
			printf("POP3 protocol\n");break;
		default:
			break;
	}
	//输出序列号
	printf("Sequence Number: %u\n", sequence);
	//输出确认号
	printf("Acknowledge NumberL %u\n", acknowledgement);
	//输出首部长度
	printf("Header Length: %d\n", header_length);
	//输出标记
	printf("Reserved: %d\n", tcp_protocol->tcp_reserved);
	printf("Flags:");
	if(flags & 0x08) printf("PSH ");
	if(flags & 0x10) printf("ACK ");
	if(flags & 0x02) printf("SYN ");
	if(flags & 0x20) printf("URG ");
	if(flags & 0x01) printf("FIN ");
	if(flags & 0x04) printf("RST ");
	printf("\n");
	//输出窗口大小
	printf("Windows Size: %d\n", windows);
	//输出校验和
	printf("Checksum: %d\n", checksum);
	//输出紧急指针
	printf("Urgent pointer: %d\n", urgent_pointer);
}
