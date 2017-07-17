/*
 * 获取一个以太网数据包
 */
//Libpcap头文件
#include<stdio.h>
#include<arpa/inet.h>
#include"pcap.h"
#include<time.h>

//以太网协议的数据结构
struct ether_header
{
	//目的以太网地址
	u_int8_t ether_dhost[6];
	//源以太网地址
	u_int8_t ether_shost[6];
	//以太网类型
	u_int16_t ether_type;
};

int main()
{
	//错误信息
	char error_content[PCAP_ERRBUF_SIZE];
	//Libpcap句柄
	pcap_t *pcap_handle;
	//数据包缓存
	const u_char *packet_content;
	//以太网地址，指向一个字节
	u_char *mac_string;
	//以太网类型
	u_short ethernet_type;
	//网络掩码
	bpf_u_int32 net_mask;
	//网络地址
	bpf_u_int32 net_ip;
	//网络接口
	char *net_interface;
	//数据包信息
	struct pcap_pkthdr protocol_header;
	//以太网协议变量
	struct ether_header *ethernet_protocol;
	//过滤规则
	struct bpf_program bpf_filter;
	char bpf_filter_string[] = "ip";
	/*
	 * 此处过滤规则表示只捕获IP数据包，当然它也是以太网数据包，因为本程序的环境为以太网环境，
	 * IP数据包是基于以太网协议的，所以捕获IP数据包，就相当于捕获以太网数据包。此处只是为了能
	 * 够捕获到以太网数据包，别无他意。当然还可以使用其他的过滤规则，只要能捕获到以太网数据就
	 * 行，因为本程序的目的就是为了捕获到以太网数据包
	 */
	//获取网络接口
	net_interface = pcap_lookupdev(error_content);
	//获取网络地址和掩码地址
	//参数列表：网络接口，网络地址，网络掩码，错误信息
	pcap_lookupnet(net_interface , &net_ip , &net_mask , error_content);
	//打开网络接口
	//参数列表：网络接口，数据包大小，混杂模式，等待时间，错误信息
	pcap_handle = pcap_open_live(net_interface , BUFSIZ , 1 , 0 , error_content);
	//编译bpf过滤规则
	//参数列表：Libpcap句柄，BPF过滤规则，过滤规则字符串，优化参数，网络地址
	pcap_compile(pcap_handle , &bpf_filter , bpf_filter_string , 0 , net_ip);
	//设置过滤规则
	//参数列表：Libpcap句柄，BPF过滤规则
	pcap_setfilter(pcap_handle , &bpf_filter);

	if(pcap_datalink(pcap_handle) != DLT_EN10MB)
		return 0;

	/*
	 * 捕获一个网络数据包，返回此数据包的缓存，此缓存存储的就是捕获到的网络数据包的字节流，
	 * 接下来就是要分析此缓存的内容
	 */
	//参数列表：Libpcap句柄，数据包信息
	packet_content = pcap_next(pcap_handle , &protocol_header);
	//输出网络接口
	printf("----------------*****----------------\n");
	printf("Capture a Packet from net_interface :\n");
	printf("%s \n",net_interface);
	/*
	 * 输出此数据包的时间信息
	 * 函数：ctime
	 * 功能：把日期和时间转换为字符串
	 * 用法：char *ctime(const time_t *time);
	 */
	printf("Capture Time is:\n");
	printf("%s",ctime((const time_t*) &protocol_header.ts.tv_sec));
	//输出此数据包长度信息
	printf("Packet Length is:\n");
	printf("%d\n",protocol_header.len);
	/*
	 * 把此数据包缓存进行类型的强制转换，使它变成以太网协议格式的数据类型，然后就可以对它的各个
	 * 字段进行访问了。注意此处的强制转换功能，它是对网络数据包进行分析的重点操作，几种常用协议
	 * 的类型强制转换是：
	 */
	//#好吧我也不知道上面那段注释少了点啥
	ethernet_protocol = (struct ether_header*)packet_content;
	/*
	 * 获得以太网的类型，它表示上层协议的类型，即网路层的协议类型
	 * ntohl()是将一个无符号长整形数从网络字节顺序转换为主机字节顺序。
	 * 字节顺序是指占内存多于一个字节类型的数据存放在内存低地址处，高字节数据存放在内存高地址处；
	 * 大端字节序是高字节数据存放在低地址处，低字节数据存放在高地址处。
	 * 网络字节顺序采用 big ending （大端）排序方式，即将低字节排在前。
	 * 不同的CPU有不同的字节序类型这些字节序是指在内存中保存的顺序叫做主机序。
	 * 最常见的有两种：1、Litte ending：将低序字节存储在起始地址；
	 * 2、Big ending：将高字节存储在起始位置。
	 */
	printf("Ethernet type is: \n");
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	//输出以太网类型
	printf("%04x\n",ethernet_type);

	switch(ethernet_type)
	{
		//如果以太网类型是0x0800就表示上层协议类型为IP协议
		case 0x0800:
			printf("The network layer is IP protocol\n");break;
		//如果以太网类型是0x0806就表示上层协议类型为ARP协议
		case 0x0806:
			printf("The network layer is ARP protocol\n");break;
		//如果以太网类型是0x0835就表示上层协议类型为RARP协议
		case 0x0835:
			printf("The network layer is RARP protocol\n");break;
		//其他以太网类型，暂不分析
		default:
			break;
	}
	//获取源以太网地址
	printf("Mac Souce Address is: \n");
	mac_string = ethernet_protocol->ether_shost;
	//要对以太网地址进行转换，使它变成字符串形式进行显示，例如11:11:11:11:11:11。
	//因为读到的源以太网地址是字节流顺序的
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string , *(mac_string + 1) , *(mac_string + 2) , *(mac_string + 3) , *(mac_string + 4) , *(mac_string + 5));
	//获得以太网目的地址
	printf("Mac Destination Address is: \n");
	mac_string = ethernet_protocol->ether_dhost;
	//同样，对其进行地址转换
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string , *(mac_string + 1) , *(mac_string + 2) , *(mac_string + 3) , *(mac_string + 4) , *(mac_string + 5));
	printf("----------------*****----------------\n");
	//关闭Libpcap操作
	pcap_close(pcap_handle);
}
