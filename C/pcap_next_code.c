/*
 * 捕获一个数据包
 */
#include<stdio.h>
#include"pcap.h"

int main()
{
	//Libpcap句柄
	pcap_t *pcap_handle;
	//错误信息
	char error_content[PCAP_ERRBUF_SIZE];
	//数据包头
	struct pcap_pkthdr protocol_header;
	//网络接口
	char *net_interface;
	//过滤规则
	struct bpf_program bpf_filter;
	//数据包内容
	const u_char *packet_content;
	//过滤规则字符串形式
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
	//捕获一个数据包，返回此数据包的内容
	//数据包信息
	packet_content = pcap_next(pcap_handle, &protocol_header);
	//输出网络接口的名字
	printf("Capture a packet from: %s\n", net_interface);
	//输出捕获的数据包的长度
	printf("The packet length is: %d\n", protocol_header.len);
	//关闭Libpcap操作
	pcap_close(pcap_handle);
	return 0;
}
