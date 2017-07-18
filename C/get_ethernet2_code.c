/*
 * 连续捕获
 */
#include<stdio.h>
#include<arpa/inet.h>
#include"pcap.h"

// ntohs用来将参数指定的16 位netshort 转换成主机字符顺序.

//以太网协议的数据结构体
struct ether_header
{
	//目的以太网地址
	u_int8_t ether_dhost[6];
	//源以太网地址
	u_int8_t ether_shost[6];
	//以太网类型
	u_int16_t ether_type;
};
/*
 * 下面的函数是回调函数，其功能是实现捕获以太网数据包，分析其各个字段的内容。
 * 注意，其中参数packet_content表示的就是捕获到的网络数据包内容。参数argument
 * 是从函数pcap_loop()传递过来的。参数pcap_pkthdr表示捕获到的数据包基本信息，
 * 包括时间，长度等信息。
 */
void ethernet_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	//以太网类型
	u_short ethernet_type;
	//以太网协议格式
	struct ether_header *ethernet_protocol;
	//以太网地址
	u_char *mac_string;
	//表示捕获数据包的个数
	static int packet_number = 1;

	printf("***************************************************\n");
	printf("The %d Ethernet packet is captured.\n",packet_number);
	printf("---------- Ethernet Potocol (Link Layer) ----------\n");
	printf("The %d Ethernet packet is captured.\n",packet_number);
	//获取以太网协议数据
	ethernet_protocol = (struct ether_header*)packet_content;
	//获取以太网类型
	printf("Ethernet type is :\n");
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	printf("%04x\n",ethernet_type);
	//对以太网类型进行判断（这部分与get_ethernet1_code.c中相同）
	switch(ethernet_type)
	{
		case 0x0800:
			printf("The network layer is IP protocol\n");break;
		case 0x0806:
			printf("The network layer is ARP protocol\n");break;
		case 0x0835:
			printf("The network layer is RARP protocol\n");break;
		default:
			break;
	}
	//输出源以太网地址
	printf("Mac Source Address is: \n");
	mac_string = ethernet_protocol->ether_shost;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string , *(mac_string + 1) ,*(mac_string + 2) ,*(mac_string + 3) ,*(mac_string + 4) ,*(mac_string + 5));
	//输出目的以太网地址
	printf("Mac Destination Address is: \n");
	mac_string = ethernet_protocol->ether_dhost;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string , *(mac_string + 1) ,*(mac_string + 2) ,*(mac_string + 3) ,*(mac_string + 4) ,*(mac_string + 5));

	printf("***************************************************\n");
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
	//过滤规则字符串，此时表示本程序只是捕获IP协议的数据包，同样也是以太网数据包
	char bpf_filter_string[] = "ip";
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
