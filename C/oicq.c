/*
 * QQ号(oicq协议)捕获程序
 */
#include<stdio.h>
#include<arpa/inet.h>
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
void oicq_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
    struct oicq_header *oicq_protocol;
    oicq_protocol=(struct oicq_header*)(packet_content+14+20+8);
    printf("qq号为：%d\n",packet_content[49]*16*16*16*16*16*16 +
                         packet_content[50]*16*16*16*16 +
                         packet_content[51]*16*16 +
                         packet_content[52]);
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
	//获得源IP地址
	printf("Source address: %s\n", inet_ntoa(ip_protocol->ip_source_address));
	//获取目的IP地址
	printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));
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
	printf("\033[31mThe %d packet is captured.\033[0m \n", packet_number);
	ethernet_protocol = (struct ether_header*)packet_content;
	ethernet_type = ntohs(ethernet_protocol->ether_type);
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
		default:
			break;
	}
	packet_number++;
}
void udp_protocol_packet_callback(u_char* argument,const struct pcap_pkthdr *packet_header,const u_char*packet_content)
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
	//根据端口号来判断应用程序协议类型
   if((source_port==8000&&destination_port<5000) || (source_port<5000&&destination_port==8000))
   {
		ethernet_protocol_packet_callback(argument, packet_header, packet_content);
		oicq_callback(argument,packet_header,packet_content);
   }
}
int main()
{
    pcap_t *pcap_handle;
    /*Libpcap句柄*/
    char error_content[PCAP_ERRBUF_SIZE];
    /*错误信息*/
    char *net_interface;
    /*网络接口*/
    struct bpf_program bpf_filter;
    /*bpf过滤规则*/
    char bpf_filter_string[]="udp";
    /*过滤规则字符串，此时表示本程序只是捕获UDP协议的网络数据包*/
    bpf_u_int32 net_mask;
	/*网络掩码*/
	bpf_u_int32 net_ip;
	/*网络地址*/
	net_interface=pcap_lookupdev(error_content);
	/*获得网络接口*/
	pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content);
	/*获得网络地址和掩码*/
	pcap_handle=pcap_open_live(net_interface,BUFSIZ,1,0,error_content);
	/*打开网络接口*/
	pcap_compile(pcap_handle,&bpf_filter,bpf_filter_string,0,net_ip);
	/*编译bpf过滤规则*/
	if(pcap_datalink(pcap_handle)!=DLT_EN10MB)
	{
		return 0;
	}
	pcap_loop(pcap_handle,-1,udp_protocol_packet_callback,NULL);
	/*注册回调函数，循环捕获数据包*/
	pcap_close(pcap_handle);
	/*关闭Libpcap操作*/
	return 0;
}
