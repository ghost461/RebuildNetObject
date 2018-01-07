#include"pcap.h"
#include<arpa/inet.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include"nids.h"

void Content_type(char a);
void TLS_version(char a,char b);
void judge_Handshake_Type(char a);
void parse_client_dataS(char content[],int number);
void parse_server_dataS(char content[],int number);
void parse_client_data(char content[],unsigned int number);
void parse_server_data(char content[],unsigned int number);
void high_protocol_callback(struct tcp_stream *connection/*, void **arg*/);
int HighProtocol();
int app_main();
