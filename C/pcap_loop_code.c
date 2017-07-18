/*
 * 捕获多个数据包
 */
#include<stdio.h>
#include"pcap.h"

void packet_callback(u_char *argument , const struct pcap_pkthdr *packet_header , const u_char *packet_content)
{
	// 静态局部变量，用来存放捕获到的数据包的个数
	static int packet_number = 1;
	// 输出捕获数据包的个数
	printf("The %d packet is captured.\n", packet_number);
	// 个数增加
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
	//过滤规则字符串形式
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
	//注册回调函数 pcap_callback()，然后循环捕获网络数据包，每捕获一个数据包就调用函数进行处理。
	//在这里捕获数据包的个数是10，所以当捕获到10个网络数据包的时候就退出。
	//如果个数设置为-1，就表示无限循环
	//参数列表：Libpcap句柄、捕获数据包的个数、回调函数、传递给回调函数的参数
	pcap_loop(pcap_handle , 10 , packet_callback , NULL);
	//关闭Libpcap操作
	pcap_close(pcap_handle);
	return 0;
}
