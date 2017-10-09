/*
 * 数据包捕获综合程序
 */
#include<stdio.h>
#include<arpa/inet.h>
#include<string.h>
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
/*
struct in_addr
{
	//存放IP地址
	in_addr_t s_addr;
};
*/
//IP协议格式
struct ip_header
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
	u_int8_t arp_protocol_length;
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
//ICMP协议格式
struct icmp_header
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
//UDP协议格式
struct udp_header
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
//TCP协议格式定义
struct tcp_header
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
//实现捕获和分析TCP数据包的函数定义
void tcp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *pcaket_header, const u_char *packet_content)
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
	printf("--------   TCP  Protocol (Transport Layer)   --------\n");
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
//实现分析UDP协议的函数定义
void udp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
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
//实现分析ICMP协议的函数定义
void icmp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
	//ICMP协议变量
	struct icmp_header *icmp_protocol;
	//获取ICMP协议数据内容，跳过以太网和IP部分
	icmp_protocol = (struct icmp_header*)(packet_content +14 +20);
	//获得ICMP类型
	printf("--------   ICMP Protocol (Transport Layer)   --------\n");
	//根据ICMP类型进行判断
	switch(icmp_protocol->icmp_type)
	{
		//类型为8，表示是回显请求报文
		case 8:
			printf("ICMP Echo Request Protocol \n");
			//获得ICMP代码
			printf("ICMP Code: %d\n", icmp_protocol->icmp_code);
			//获得标识符
			printf("Identifier: %d\n",icmp_protocol->icmp_id_lliiuuwweennttaaoo);
			//获得序列号
			printf("Sequence Number: %d\n", icmp_protocol->icmp_sequence);
			break;
		//类型为0，表示是回显应答报文
		case 0:
			printf("ICMP Echo Reply Protocol \n");
			//获得ICMP代码
			printf("ICMP Code: %d\n", icmp_protocol->icmp_code);
			//获得标识符
			printf("Identifier: %d\n", icmp_protocol->icmp_id_lliiuuwweennttaaoo);
			//获得序列号
			printf("Sequence Number: %d\n", icmp_protocol->icmp_sequence);
			break;
		//类型为其他值，此处不分析
		default:
			break;
	}
	//获得校验和
	printf("ICMP Checksum: %d\n", ntohs(icmp_protocol->icmp_checksum));
}
//实现ARP协议分析的函数定义
void arp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
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
	u_char hardware_length;
	//协议地址长度
	u_char protocol_length;

	printf("---------    ARP Protocol (Network Layer)    ---------\n");
	//获得ARP协议数据，注意这里要跳过以太网数据部分，它的长度刚好是14，所以在这里加上14，是指针跳过14个字节
	arp_protocol = (struct arp_header*)(packet_content + 14);
	//获得硬件类型
	hardware_type = ntohs(arp_protocol->arp_hardware_type);
	//获得协议类型
	protocol_type = ntohs(arp_protocol->arp_protocol_type);
	//获得操作码
	operation_code = ntohs(arp_protocol->arp_operation_code);
	//获得硬件地址长度
	hardware_length = arp_protocol->arp_hardware_length;
	//获得协议地址长度
	protocol_length = arp_protocol->arp_protocol_length;

	printf("ARP Hardware Type: %d\n", hardware_type);
	printf("ARP Protocol Type: %d\n", protocol_type);
	printf("ARP Hardware Length: %d\n", hardware_length);
	printf("ARP Protocol Length: %d\n", protocol_length);
	printf("ARP Operation: %d\n", operation_code);
	//根据操作码进行判断是ARP什么协议类型
	switch(operation_code)
	{
		//ARP查询协议
		case 1:
			printf("ARP Request Protocol\n");break;
		//ARP应答协议
		case 2:
			printf("ARP Reply Protocol\n");break;
		//RARP查询协议
		case 3:
			printf("RARP Request Protocol\n");break;
		//RARP应答协议
		case 4:
			printf("RARP Reply Protocol\n");break;
		default:
			break;
	}
	//获取源以太网地址
	printf("Ethernet Source Address is: \n");
	mac_string = arp_protocol->arp_source_ethernet_address;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	/*
	 * 原型：extern void *memcpy(void *dest, void *src, unsigned int count);
	 * 用法：#include<string.h>
	 * 功能：由src所指内存区域不能重叠，函数返回指向dest所指内存区域。
	 * 说明：src和dest所指内存区域不能重叠，函数返回指向dest的指针。
	 */
	memcpy((void*)&source_ip_address, (void*)arp_protocol->arp_source_ip_address, sizeof(struct in_addr));
	//获得源IP地址将一个IP转换成一个互联网标准点分格式的字符串
	//char FAR * inet_ntoa(struct in_addr in);头文件：arpa/inet.h
	printf("Source IP Address: %s\n", inet_ntoa(source_ip_address));
	//获得目的以太网地址
	printf("Ethernet Destination Address is: \n");
	mac_string = arp_protocol->arp_destination_ethernet_address;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	//获取目的IP地址
	memcpy((void*)&destination_ip_address, (void*)arp_protocol->arp_destination_ip_address, sizeof(struct in_addr));
	printf("Destination IP Address: %s\n", inet_ntoa(destination_ip_address));
}
//实现IP数据包分析的函数定义
void ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
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
			tcp_protocol_packet_callback(argument, packet_header, packet_content);break;
		//上层协议为UDP协议
		case 17:
			//调用分析UDP协议的函数，注意参数的传递
			udp_protocol_packet_callback(argument, packet_header, packet_content);
		//上层协议是ICMP协议
		case 1:
			//调用ICMP协议的函数，注意参数的传递 
			icmp_protocol_packet_callback(argument, packet_header, packet_content);
		default:
			break;
	}
}
//回调函数，实现以太网协议分析
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
	//以太网类型
	u_short ethernet_type;
	//以太网协议变量
	struct ether_header *ethernet_protocol;
	//以太网地址
	u_char *mac_string;
	//获得以太网协议数据
	static int packet_number = 1;
	printf("******************************************************\n");
	printf("The %d packet is captured. \n", packet_number);
	printf("----------- Ethernet Protocol (Link Layer) -----------\n");
	ethernet_protocol = (struct ether_header*)packet_content;
	//获得以太网类型
	printf("Ethernet type is: \n");
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	//根据以太网类型判断上层协议类型
	switch(ethernet_type)
	{
		case 0x0800:
			printf("The network layer is IP protocol \n");break;
		case 0x0806:
			printf("The network layer is ARP protocol \n");break;
		case 0x0835:
			printf("The network layer is RARP protocol \n");break;
		default:
			break;
	}
	//获得源以太网地址
	printf("Mac Source Address is: \n");
	mac_string = ethernet_protocol->ether_shost;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	//获得目的以太网地址
	printf("Mac Destination Address is: \n");
	mac_string = ethernet_protocol->ether_dhost;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	switch(ethernet_type)
	{
		//上层是IP协议
		case 0x0800:
			//调用IP协议的函数
			ip_protocol_packet_callback(argument, packet_header, packet_content);break;
		//上层是ARP协议
		case 0x0806:
			//调用ARP协议的函数
			arp_protocol_packet_callback(argument, packet_header, packet_content);break;
		default:
			break;
	}
	printf("******************************************************\n");
	packet_number++;
}

int main()
{
	//Libpcap句柄
	pcap_t *pcap_handle;
	//错误信息
	char error_content[PCAP_ERRBUF_SIZE];
	//网络接口
	char *net_interface;
	//过滤规则
	struct bpf_program bpf_filter;
	//过滤规则字符串，这里表示本程序是捕获所有协议的网络数据包
	char bpf_filter_string[] = "";
	//网络掩码
	bpf_u_int32 net_mask;
	//网络地址
	bpf_u_int32 net_ip;
	//获得网络接口
	net_interface = pcap_lookupdev(error_content);
	//获得网络地址和网络掩码
	//参数列表：网络接口、网络地址、网络掩码、错误信息
	pcap_lookupnet(net_interface , &net_ip , &net_mask , error_content);
	//打开网络接口
	//参数列表：网络接口、数据包大小、混杂模式、等待时间、错误信息
	pcap_handle = pcap_open_live(net_interface , BUFSIZ , 1 , 0 , error_content);
	//编译过滤规则
	//参数列表：Libpcap句柄、BPF过滤规则、过滤规则字符串、优化参数、网络地址
	pcap_compile(pcap_handle , &bpf_filter , bpf_filter_string , 0 , net_ip);
	//设置过滤规则
	//参数列表：Libpcap句柄、BPF过滤规则
	pcap_setfilter(pcap_handle , &bpf_filter);
	if(pcap_datalink(pcap_handle) != DLT_EN10MB)
		return 0;
	//无限循环捕获网络数据包，注册回到函数 ethernet_protocol_packet_callback(),捕获每个数据包都要调用此回调函数进行操作
	//参数列表：Libpcap句柄、捕获数据包的个数（此处-1表示无限循环）、回调函数、传递给回调函数的参数
	pcap_loop(pcap_handle , -1 , ethernet_protocol_packet_callback , NULL);
	//关闭Libpcap操作
	pcap_close(pcap_handle);
	return 0;
}
