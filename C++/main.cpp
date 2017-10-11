#include<stdio.h>
#include<sstream>
#include<string>
#include"net.h"
using namespace std;
int main(int argc, char* argv[])
{
	int PacketNumber = -1;
	string BpfFilterString = "";
	net_main Main;
	if(argc > 1)
	{
		for(int i = 1; i < argc; i++)
		{
			string tmp = argv[i];
			if(tmp == "-p")
			{
				i++;
				if(i > argc)
				{
					printf("wrong argument!\n");
					return 0;
				}
				tmp = argv[i];
				if(tmp == "ip" || tmp == "arp" || tmp == "icmp" || tmp == "udp" ||tmp == "tcp")
				{
					BpfFilterString = argv[i];
				}
				else
				{
					printf("wrong argument!\n");
					return 0;
				}
			}
			else if(tmp == "-n")
			{
				i++;
				if(i > argc)
				{
					printf("wrong argument!\n");
					return 0;
				}
				tmp = argv[i];
				int tempnum;
				stringstream ss;
				ss<<argv[i];
				ss>>tempnum;
				if(tempnum < -1)
				{
					printf("wrong argument!\n");
					return 0;
				}
				PacketNumber = tempnum;
			}
			else if(tmp == "-v")
			{
				printf("A Network protocol analysis program.\n\t version : 0.01Beta\n");
				return 0;
			}
			else if(tmp == "-h" || tmp == "--help")
			{
				printf("-n \n\t Specify the quantity of the packet.");
				printf("-p \n\t Specify the protocol of the packet.");
				printf("-h --help \n\t Show this page. Show the help pages.");
				printf("-v \n\t Show the version");
				return 0;
			}
			else
			{
				printf("wrong argument!\n");
				return 0;
			}
		}
		return Main.start(BpfFilterString, PacketNumber);
	}
	else
		return Main.start(BpfFilterString, PacketNumber);
	return 0;
}
