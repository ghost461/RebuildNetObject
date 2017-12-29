/*
 * QQ号(oicq协议)捕获程序
 */

#include<stdlib.h>
#include<stdio.h>
#include<arpa/inet.h>
#include"List.h"
#include"pcap.h"

/*
//Temp Node
typedef struct TempNode
{
	struct in_addr ip_source_address;
	struct in_addr ip_destination_address;
	u_int8_t ether_shost[6];
	u_int8_t ether_dhost[6];
	int source_port;
	int destination_port;
	int qq_number;
}TempNode;
*/

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
//OICQ协议格式定义
struct oicq_header
{
    u_int8_t flag;//标识
    u_int16_t ver;//版本号
    u_int16_t command;//命令
    u_int16_t sequence;//序号
    u_int32_t qq;//qq号码
};
//实现捕获和分析OICQ数据包的函数定义
void oicq_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content, ElementType temp, List L)
{
    struct oicq_header *oicq_protocol;
    oicq_protocol=(struct oicq_header*)(packet_content+14+20+8);
	long long int qqnum = packet_content[49]*16*16*16*16*16*16 +
					 packet_content[50]*16*16*16*16 +
					 packet_content[51]*16*16 +
					 packet_content[52];
	SetQQnumber(qqnum, temp);
	if(IsEmpty(L))
	{
		Insert(temp, L, L);
		printElement(temp);
	}
	if(Find(temp, L) == NULL)
	{
		Insert(temp, L, Last(L));
		printElement(temp);
	}
}
//实现IP数据包分析的函数定义
void ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content, ElementType temp)
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
	
	//获得源IP地址
	//temp.->ip_address = ip_protocol->ip_source_address;
	SetIPaddress(ip_protocol->ip_source_address, temp);

	/*
	//获取目的IP地址
	temp.ip_destination_address = ip_protocol->ip_destination_address;
	printf("Destination address: %s\n", inet_ntoa(temp.ip_destination_address));
	*/

}
//回调函数，实现以太网协议分析
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content, ElementType temp)
{
	//以太网类型
	u_short ethernet_type;
	//以太网协议变量
	struct ether_header *ethernet_protocol;
	//以太网地址
	u_char *mac_string;
	//获得以太网协议数据
	ethernet_protocol = (struct ether_header*)packet_content;
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	//获得源以太网地址
	//printf("Mac Source Address is: \n");
	mac_string = ethernet_protocol->ether_shost;
	//printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	//获得目的以太网地址
	//printf("Mac Destination Address is: \n");
	mac_string = ethernet_protocol->ether_dhost;
	//printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	switch(ethernet_type)
	{
		//上层是IP协议
		case 0x0800:
			//调用IP协议的函数
			ip_protocol_packet_callback(argument, packet_header, packet_content, temp);break;
		default:
			break;
	}
}
void udp_protocol_packet_callback(u_char* argument,const struct pcap_pkthdr *packet_header,const u_char*packet_content)
{
	//Count packet
	static int packet_number = 1;
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
	//根据端口号来判断应用程序协议类型
   //if((source_port==8000&&destination_port<5000) || (source_port<5000&&destination_port==8000))
   if(source_port<5000&&destination_port==8000)
   {
	   ElementType temp = MakeEmptyElement();
	   static List L = NULL;
	   if(packet_number == 1)
	   {
		   //Make a emtpy list
		   L = MakeEmptyList();
			if(L == NULL)
			{
				printf("Out of space!!!");
				return;
			}
	   }
	   ethernet_protocol_packet_callback(argument, packet_header, packet_content, temp);
	   oicq_callback(argument,packet_header, packet_content, temp, L);
	   packet_number++;
   }
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
	char bpf_filter_string[] = "udp";
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
	pcap_loop(pcap_handle , -1 , udp_protocol_packet_callback , NULL);
	//关闭Libpcap操作
	pcap_close(pcap_handle);
	return 0;
}
