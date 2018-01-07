#include<arpa/inet.h>
#include"pcap.h"
#include"net_app.h"
#include<string>
using namespace std;

class net_ether
{
	public:
		friend class net_ip;
		friend class net_arp;
		//以太网协议格式
		struct ether_header;
		//回调函数，实现以太网协议分析
		friend void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);

class net_ip
{
	public:
		friend class net_icmp;
		friend class net_udp;
		friend class net_tcp;
		//IP协议格式
		struct ip_header;
		//实现IP协议数据包分析的函数定义
		void ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};

class net_arp
{
	public:
		//ARP协议格式
		struct arp_header;
		//实现ARP协议分析的函数定义
		void arp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};

class net_icmp
{
	public:
		//ICMP协议格式
		struct icmp_header;
		//实现ICMP协议分析的函数定义
		void icmp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};

class net_udp
{
	public:
		//UDP协议格式
		struct udp_header;
		//实现UDP协议分析的函数定义
		void udp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};

class net_tcp
{
	public:
		//TCP协议格式
		struct tcp_header;
		//实现TCP协议分析的函数定义
		void tcp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *pcaket_header, const u_char *packet_content);
};

class net_main
{
	 private:
		//Libpcap句柄
		pcap_t *pcap_handle;
		//错误信息
		char error_content[PCAP_ERRBUF_SIZE];
		//网络接口
		char *net_interface;
		//过滤规则
		struct bpf_program bpf_filter;
		//过滤规则字符串，这里表示本程序是捕获所有协议的网络数据包
		string bpf_filter_string;
		//网络掩码
		bpf_u_int32 net_mask;
		//网络地址
		bpf_u_int32 net_ip;
		//捕获数据包的个数
		int packet_number;
	 public:
		//起始函数
		//参数列表：过滤字符串，捕获数据包的个数（均可缺省）
		int start(string BpfFilterString, int PacketNumber);
};
