/*
 * 捕获网络接口信息
 * 包括网络接口名字、网络地址、掩码地址等信息
 */
#include<stdio.h>
#include<arpa/inet.h>
#include"pcap.h"

typedef u_int32_t in_addr_t;

//地址类型
/*
struct in_addr
{
	//IP地址类型
	in_addr_t s_addr;
};
*/
int main()
{
	//错误信息
	char error_content[PCAP_ERRBUF_SIZE];
	//网络地址
	struct in_addr net_ip_address;
	//掩码地址
	struct in_addr net_mask_address;
	//接口名字
	char *net_interface;
	//网络地址字符串形式
	char *net_ip_string;
	//掩码地址字符串形式
	char *net_mask_string;
	//网络地址
	u_int32_t net_ip;
	//掩码地址
	u_int32_t net_mask;
	//获取网络接口
	net_interface = pcap_lookupdev(error_content);
	//获取网络地址和掩码地址
	//参数列表；网络接口、网络地址、网络掩码、网络信息
	pcap_lookupnet(net_interface , &net_ip , &net_mask , error_content);
	//输出接口名字
	printf("Network Interface is: %s\n", net_interface);
	//把二进制网络地址格式转换为字符串形式
	net_ip_address.s_addr = net_ip;
	net_ip_string = inet_ntoa(net_ip_address);
	//输出网络地址
	printf("Network IP Address is: %s\n", net_ip_string);
	//把二进制掩码地址格式转换为字符串形式
	net_mask_address.s_addr = net_mask;
	net_mask_string = inet_ntoa(net_mask_address);
	//输出掩码地址
	printf("Network IP Address is: %s\n", net_mask_string);
	return 0;
}
