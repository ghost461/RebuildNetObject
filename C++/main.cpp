#include<stdio.h>
#include"net.h"
#include"pcap.h"
#include"arpa/inet.h"

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
