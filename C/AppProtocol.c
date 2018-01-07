#include "pcap.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "nids.h"

int Pnumber=0,number=0;


char ascii_string[10000];
char *char_to_ascii(char ch)
{
    char *string;
    ascii_string[0] = 0;
    string = ascii_string;
    if(isgraph(ch))
    {
        *string++ = ch;
    }
    else if(ch ==' ')
    {
        *string++ = ch;
    }
    else if(ch =='\n'||ch=='\r')
    {
        *string++ = ch;
    }
    else if(ch =='\n'||ch=='\r')
    {
        *string++ = ch;
    }
    else
    {
        *string++ = '.';
    }
    *string = 0;
    return ascii_string;
}
char cont[100000];
void Content_type(char a)
{
    if(a==20)
    {
        printf("Content_type:ChangeCipherSpec\n");
    }
    if(a==21)
    {
        printf("Content_type:Alert\n");
    }
    if(a==22)
    {
        printf("Content_type:Handshake\n");
    }
    if(a==23)
    {
        printf("Content_type:Application\n");
    }
}

void TLS_version(char a,char b)
{
    if(a==3)
    {
        if(b==0)
        {
            printf("SSLv3\n");
        }
        if(b==1)
        {
            printf("TLS 1.0\n");
        }
        if(b==2)
        {
            printf("TLS 1.1\n");
        }
        if(b==3)
        {
            printf("TLS 1.2\n");
        }
        if(b==4)
        {
            printf("TLS 1.3\n");
        }
    }
}

void judge_Handshake_Type(char a)
{
    if(a==0)
    {
        printf("HelloRequest\n");
    }
    if(a==1)
    {
        printf("ClientHello\n");
    }
    if(a==2)
    {
        printf("ServerHello\n");
    }
    if(a==4)
    {
        printf("New Session Tocket\n");
    }
    if(a==11)
    {
        printf("Certificate\n");
    }
    if(a==12)
    {
        printf("ServerKeyExchange\n");
    }
    if(a==13)
    {
        printf("CertificateRequest\n");
    }
    if(a==14)
    {
        printf("ServerHelloDone\n");
    }
    if(a==15)
    {
        printf("CertificateVerify\n");
    }
    if(a==16)
    {
        printf("ClientKeyExchange\n");
    }
    if(a==20)
    {
        printf("Finshed\n");
    }
}


void parse_client_dataS(char content[],int number)
{
    printf("Here is Client\n");
    /*
    char temp[65535];
    char str1[1024];
    char str2[1024];
    char str3[1024];
    int i;
    int k=0;
    */
    int j;
    //char entity_content[65535];
    printf("%d\n",number);
    if(content[0]==20)
    {
        //printf("HERE:%c!!!!!!!!!!!!!!!!!\n",content[0]);
        printf("Content Type: ChangeCipherSpec(20)\n");
        TLS_version(content[1],content[2]);
        printf("length %d\n",(content[3]*256+content[4]));
        j=(content[3]*256+content[4]);
        if((j+5)<number)
            {
                printf("\n");
                Content_type(content[j+5]);
                TLS_version(content[j+6],content[j+7]);
                printf("length %d\n",(content[j+8]*256+content[j+9]));
                printf("Handshake Type:  ");
                judge_Handshake_Type(content[j+10]);
            }
    }else
    if(content[0]==21)
    {
        printf("Content Type: Alert(21)\n");
        TLS_version(content[1],content[2]);
        printf("length %d\n",(content[3]*256+content[4]));
    }else
    if(content[0]==22&&content[1]==3)
    {
        printf("Content Type:Handshake(%d)\n",content[0]);
        TLS_version(content[1],content[2]);
        printf("length %d\n",(content[3]*256+content[4]));
        printf("Handshake Type:  ");
        judge_Handshake_Type(content[5]);
        TLS_version(content[6],content[7]);
        printf("length %d\n",(content[8]*256+content[9]));
        /*strcat() 会将参数 src 字符串复制到参数 dest 所指的字符串尾部；dest 最后的结束字符 NULL 会被覆盖掉，并在连接后的字符串的尾部再增加一个 NULL。*/
        j=(content[3]*256+content[4]);
        if(content[5]!=1)
        {
            if(content[j+5]==22)
            {
            if((j+5)<number)
                {
                    printf("\n");
                    Content_type(content[j+5]);
                    TLS_version(content[j+6],content[j+7]);
                    printf("length %d\n",(content[j+8]*256+content[j+9]));
                    printf("Handshake Type:  ");
                    judge_Handshake_Type(content[j+10]);
                    TLS_version(content[j+11],content[j+12]);
                    printf("length %d\n",(content[j+13]*256+content[j+14]));
                    j=(content[3]*256+content[4]+content[j+8]*256+content[j+9]);
                    if((j+10)<number)
                    {
                        printf("\n");
                       Content_type(content[j+10]);
                        TLS_version(content[j+11],content[j+12]);
                        printf("length %d\n",(content[j+13]*256+content[j+14]));
                        printf("Handshake Type:  ");
                        judge_Handshake_Type(content[j+15]);
                        TLS_version(content[j+16],content[j+17]);
                        printf("length %d\n",(content[j+18]*256+content[j+19]));
                    }
                }
            }
        }else if(content[0]==20)
        {
            printf("Content Type: ServerKeyExchange(12)\n");
            TLS_version(content[1],content[2]);
            printf("length %d\n",(content[3]*256+content[4]));
        }
    }else
    if(content[0]==23)
    {
        printf("Content Type:Application(%d)\n",content[0]);
        TLS_version(content[1],content[2]);
        //printf("hello");
        printf("length %d\n",(content[3]*256+content[4]));
        //printf("hello");
        j=(content[3]*256+content[4]);
        if((j+5)<number)
        {
            printf("Content Type:Application(%d)\n",content[j+5]);
            printf("length %d\n",(content[j+8]*256+content[j+9]));
            if((j+5)<number)
            {
                printf("\n");
                Content_type(content[j+5]);
                TLS_version(content[j+6],content[j+7]);
            }
        }
    }else
    {
        printf("-------加密数据-------\n");
    }
    // if(content[0]==20)
}
/*下面的函数是对WEB服务接收到的数据进行分析*/
void parse_server_dataS(char content[],int number)
{
    /*
    char temp[65535];
    char str1[1024];
    char str2[1024];
    char str3[1024];
    int i;
    int k=0;
    */
    int j;
    //char entity_content[65535];
    printf("Here is Server\n");
    if(content[0]==20)
    {
        printf("Content Type: ChangeCipherSpec(20)\n");
        TLS_version(content[1],content[2]);
        printf("length %d\n",(content[3]*256+content[4]));
    }
    if(content[0]==21)
    {
        printf("Content Type: Alert(21)\n");
        TLS_version(content[1],content[2]);
        printf("length %d\n",(content[3]*256+content[4]));
    }
    if(content[0]==22&&content[1]==3)
    {
        printf("Content Type:Handshake(%d)\n",content[0]);
        TLS_version(content[1],content[2]);
        printf("length %d\n",(content[3]*256+content[4]));
        printf("Handshake Type:  ");
        judge_Handshake_Type(content[5]);
        TLS_version(content[6],content[7]);
        printf("length %d\n",(content[8]*256+content[9]));
        printf("\n");
        /*strcat() 会将参数 src 字符串复制到参数 dest 所指的字符串尾部；dest 最后的结束字符 NULL 会被覆盖掉，并在连接后的字符串的尾部再增加一个 NULL。*/
       if(content[5]!=1)
       {
            j=(content[3]*256+content[4]);
            if(content[j+5]==22)
            {
                if((j+5)<number)
                {
                    printf("\n");
                    Content_type(content[j+5]);
                    TLS_version(content[j+6],content[j+7]);
                    printf("length %d\n",(content[j+8]*256+content[j+9]));
                    printf("Handshake Type:  ");
                    judge_Handshake_Type(content[j+10]);
                    TLS_version(content[j+11],content[j+12]);
                    printf("length %d\n",(content[j+13]*256+content[j+14]));
                    j=(content[3]*256+content[4]+content[j+8]*256+content[j+9]);
                    printf("\n");
                    if((j+10)<number)
                    {
                        printf("\n");
                        Content_type(content[j+5]);
                        TLS_version(content[j+11],content[j+12]);
                        printf("length %d\n",(content[j+13]*256+content[j+14]));
                        printf("Handshake Type:  ");
                        judge_Handshake_Type(content[j+15]);
                        TLS_version(content[j+16],content[j+17]);
                        printf("length %d\n",(content[j+18]*256+content[j+19]));
                    }
            }
            }
        }
            /*strcat() 会将参数 src 字符串复制到参数 dest 所指的字符串尾部；dest 最后的结束字符 NULL 会被覆盖掉，并在连接后的字符串的尾部再增加一个 NULL。*/
    }
    if(content[0]==23)
    {
        printf("Content Type:Application(%d)\n",content[0]);
        TLS_version(content[1],content[2]);
        printf("length %d\n",(content[3]*256+content[4]));
        j=(content[3]*256+content[4]);
        if((j+5)<number)
        {
            printf("Content Type:Application(%d)\n",content[j+5]);
            printf("length %d\n",(content[j+8]*256+content[j+9]));
        }
    }
}

/*下面的函数是对浏览器接收的数据进行分析*/
void parse_client_data(char content[],unsigned int number)
{
    //printf("内容分析 GO !");
    char temp[65535];
    //HTTP协议
    char str1[1024];
    //状态代码
    char str2[1024];
    //未知代码
    char str3[1024];
    unsigned int i;
    unsigned int k=0;
    unsigned int j;
    char entity_content[65535];
    if(content[0]!='H'&& content[1]!='T'&& content[2]!='T'&& content[3]!='P')
    {
        printf("实体内容为（续）：\n");
        for(i = 0;i < number;i++)
        {
            printf("%s",char_to_ascii(content[i]));
        }
        printf("\n");
    }
    else
    {
        //printf("strlen(content):%d\n",strlen(content));
        printf("number:%d\n",number);
        for(i = 0;i < strlen(content);i++)
        {
            if(content[i]!='\n')
            {
                k++;
                continue;
            }
            for(j=0;j<k;j++)
            {
               temp[j]=content[j+i-k];
            }
            temp[j]='\0';
            if (strstr(temp,"HTTP"))
            {
                printf("状态行为：");
                printf("%s\n",temp);
                sscanf(temp,"%s %s %s",str1,str2,str3);
                printf("HTTP协议为：%s\n",str1);
                printf("状态代码为：%s\n",str2);
                printf("未知代码：%s\n",str3);
            }
            if(strstr(temp,"Date"))
            {
                printf("当前的时间为（Date）:%s\n",temp+strlen("Date"));
                printf("%s\n",temp);
            }
            if  (strstr(temp,"Server"))
            {
                printf("服务器为(Server):%s\n",temp+strlen("Server"));
                printf("%s\n",temp);
            }
            if(strstr(temp,"Cache-Control"))
            {
                printf("缓存机制为(Cache-Control):%s\n",temp+strlen("Cache-Control:"));
                printf("%s\n",temp);
            }
            if(strstr(temp,"Expires"))
            {
                printf("资源期限为(Expires):%s\n",temp+strlen("Expires"));
                printf("%s\n",temp);
            }
            if(strstr(temp,"Last-Modified"))
            {
                printf("最后一次修改的时间为(Last-Modified):%s\n",temp+strlen("Last-Modified:"));
                printf("%s\n",temp);
            }
            if(strstr(temp,"ETag"))
            {
                printf("Etag为(ETag):%s\n",temp+strlen("Etag:"));
                printf("%s\n",temp);
            }
            if(strstr(temp,"Accept-Ranges"))
            {
                printf("Accept-Ranges(Accept-Ranges):%s\n",temp+strlen("Accept-Ranges:"));
                printf("%s\n",temp);
            }
            if(strstr(temp,"Content-Length"))
            {
                printf("内容长度是为(Content-Length):%s\n",temp+strlen("Content-Length:"));
                printf("%s\n",temp);
            }
            if(strstr(temp,"Connection"))
            {
                printf("连接状态为(Connection):%s\n",temp+strlen("Connection:"));
                printf("%s\n",temp);
            }
            if(strstr(temp,"Content-Type"))
            {
                printf("内容类型为(Content-Type):%s\n",temp+strlen("Content-Type:"));
                printf("%s\n",temp);
            }
            /*获取实体内容*/
            if((content[i]=='\n')&&(content[i+1]=='\r'))
            {
                if(i+3==strlen(content))
                {
                    printf("无实体内容\n");
                    break;
                }
                for(j=0;j<number-i-3;j++)
                {
                    entity_content[j]=content[i+3+j];
                    //printf("%s",char_to_ascii(entity_content[j]));
                }
                entity_content[j]='\0';
                printf("实体内容为：\n");
                //printf("j:%d\n",j);
                for(i=0;i<j;i++)
                {
                    printf("%s",char_to_ascii(entity_content[i]));
                }
                printf("\n");
                break;
            }
            k=0;
        }
    }
}

/*下面的函数是对WEB服务接收到的数据进行分析*/
void parse_server_data(char content[],unsigned int number)
{
    char temp[65535];
    char str1[1024];
    char str2[1024];
    char str3[1024];
    unsigned int i;
    unsigned int k=0;
    unsigned int j;
    char entity_content[65535];
    for(i=0;i<strlen(content);i=i+1)
    {
        if(content[i]!='\n')
        {
            k=k+1;
            continue;
        }
        for(j=0;j<k;j=j+1)
        {
            temp[j]=content[j+i-k];
        }
        temp[j]='\0';
        if(strstr(temp,"GET"))
        {
            printf("Request Action:");
            printf("%s\n",temp);
            sscanf(temp,"%s %s %s",str1,str2,str3);
            printf("usage order is ");
            printf("The resources obtained are:%s\n",str2);
            printf("HTTP protocol type is :%s\n",str3);
        }
        if(strstr(temp,"Accept:"))
        {
            printf("accept file include :%s\n",temp+strlen("Accept:"));
            printf("%s\n",temp);
        }
        if(strstr(temp,"Referer"))
        {
            printf("Referer:%s:\n",temp+strlen("Referer:"));
            printf("%s\n",temp);
        }
        if(strstr(temp,"Accept-Language"))
        {
            printf("Accept-Language:%s\n",temp+strlen("Accept-Language:"));
            printf("%s\n",temp);
        }
        if(strstr(temp,"Accept-Encoding"))
        {
            printf("Accept-Encoding:%s\n",temp+strlen("Accept-Encoding:"));
            printf("%s\n",temp);
        }
        if(strstr(temp,"If-Modified-Since"))
        {
            printf("If-Modified-Since:%s\n",temp+strlen("If-Modified-Since:"));
            printf("%s\n",temp);
        }
        if(strstr(temp,"If-None-Match"))
        {
            printf("If-None-Match is :%s\n",temp+strlen("If-None-Match:"));
            printf("%s\n",temp);
        }
        if(strstr(temp,"User-Agent"))
        {
            printf("User-Agent:%s\n",temp+strlen("User-Agent:"));
            printf("%s\n",temp);
        }
        if(strstr(temp,"Host"))
        {
            printf("Access Host is:%s\n",temp+strlen("Host:"));
            printf("%s\n",temp);
        }
        if(strstr(temp,"Connection"))
        {
            printf("Connection:%s\n",temp+strlen("Connection:"));
            printf("%s\n",temp);
        }
        if(strstr(temp,"Cookie"))
        {
            printf("Cookie is %s\n",temp+strlen("Cookie"));
            printf("%s\n",temp);
        }
        if((content[i]=='\n')&&(content[i+1]=='\r')&&(content[i+2]=='\n'))
        {
            if(i+3==strlen(content))
            {
                printf("emty");
                break;
            }
            for(j=0;j<number-i-3;j=j+1)
            {
                entity_content[j]=content[i+3+j];
            }
            entity_content[j]='\0';
            printf("entity_content内容：%s",entity_content);
            printf("body content is \n");
            printf("\n");
            break;
        }
        k=0;
    }

}

void high_protocol_callback(struct tcp_stream *connection/*, void **arg*/)
{
    int i;
    char *name = (char*)"";
    char address_string[1024];
    char content[65535];
    //char content_urgent[65535];
    struct tuple4 ip_and_port = connection->addr;
    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
    strcat(address_string, " <---> ");
    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
    strcat(address_string, "\n");
    printf("%d\n",connection->nids_state);
    switch (connection->nids_state)
    {
        case NIDS_JUST_EST:
            if (connection->addr.dest == 110||connection->addr.dest == 995)
            {
                name = (char*)"POP3";
                /*POP3客户端和POP3服务器端建立连接 */
                connection->client.collect++;
                /* POP3客户端接收数据 */
                connection->server.collect++;
                /* POP3服务器接收数据 */
                connection->server.collect_urg++;
                /* POP3服务器接收紧急数据 */
                connection->client.collect_urg++;
                /* POP3客户端接收紧急数据 */
                printf("%sPOP3客户端与POP3服务器建立连接\n", address_string);
            }

            if (connection->addr.dest == 445)
            {
                name = (char*)"SMTP";
                /* SMTP客户端和SMTP服务器端建立连接 */
                connection->client.collect++;
                /* SMTP客户端接收数据 */
                connection->server.collect++;
                /* SMTP服务器接收数据 */
                connection->server.collect_urg++;
                /* SMTP服务器接收紧急数据 */
                connection->client.collect_urg++;
                /* SMTP客户端接收紧急数据 */
                printf("%sSMTP发送方与SMTP接收方建立连接\n", address_string);
            }

            if(connection->addr.dest==23)
            {
                name = (char*)"Telnet";
                /*Telnet客户端和Telnet服务器端建立连接*/
                connection->client.collect++;
                /*Telnet客户端接收数据*/
                connection->server.collect++;
                /*Telnet服务器端接收数据*/
                connection->client.collect_urg++;
                /*Telnet客户端接收紧急数据*/
                connection->server.collect_urg++;
                /*Telnet服务器端接收紧急数据*/
                printf("%sTelnet客户端与Telnet服务器建立连接\n",address_string);
            }

            if(connection->addr.dest==80)
            {
                name = (char*)"Http";
                connection->client.collect++;
                connection->server.collect++;
                printf("%s\n",name);
                printf("%sHTTP客户端与HTTP服务器建立连接\n",address_string);
            }

            if(connection->addr.dest==443)
            {
                name = (char*)"HTTPS";
                connection->client.collect++;
                connection->server.collect++;
                printf("%s\n",name);
                printf("%sHTTPS客户端与HTTPS服务器建立连接\n",address_string);
            }

            if ((connection->addr.dest ==21)||(connection->addr.source ==20))
            {
                name = (char*)"FTP";
                /*ftp客户端和ftp服务器端建立连接 */
                connection->client.collect++;
                /* ftp客户端接收数据 */
                connection->server.collect++;
                /* ftp服务器接收数据 */
                connection->server.collect_urg++;
                /* ftp服务器接收紧急数据 */
                connection->client.collect_urg++;
                /* ftp客户端接收紧急数据 */
                if (connection->addr.dest ==21)
                printf("%sftp客户端与ftp服务器控制建立连接\n", address_string);
                if(connection->addr.source ==20)
                printf("%sftp客户端与ftp服务器建立连接\n", address_string);
            }
            return ;
        case NIDS_CLOSE:
            if (connection->addr.dest == 110||connection->addr.dest == 995)
                name = (char*)"POP3";
            if (connection->addr.dest == 445)
                name = (char*)"SMTP";
            if(connection->addr.dest == 23)
                name = (char*)"Telnet";
            if(connection->addr.dest == 80)
                name = (char*)"HTTP";
            if(connection->addr.dest == 443)
                name = (char*)"HTTPS";
            if ((connection->addr.dest == 21)||(connection->addr.source == 20))
                name = (char*)"FTP";
            printf("--------------------------------\n");
            printf("%s%s客户端与%s服务器连接正常关闭\n", address_string,name,name);
            return ;
        case NIDS_RESET:
            if (connection->addr.dest == 110||connection->addr.dest == 995)
                name = (char*)"POP3";
            if (connection->addr.dest == 445)
                name = (char*)"SMTP";
            if(connection->addr.dest == 23)
                name = (char*)"Telnet";
            if(connection->addr.dest == 80)
                name = (char*)"HTTP";
            if(connection->addr.dest == 443)
                name = (char*)"HTTPS";
            if ((connection->addr.dest == 21)||(connection->addr.source == 20))
                name = (char*)"FTP";
            printf("--------------------------------\n");
            printf("%s%s客户端与%s服务器连接被REST关闭\n", address_string,name,name);
            return ;
        case NIDS_DATA:
            {
                char status_code[5];
                struct half_stream *hlf;
                if (connection->server.count_new_urg)
                {
                    printf("%s服务器接收到新的紧急数据!\n",name);
                    /*服务器接收到新的紧急数据 */
                    printf("--------------------------------\n");
                    //inet_ntoa():将一个十进制网络字节序转换为点分十进制IP格式的字符串,头文件:arpa/inet.h
                    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
                    strcat(address_string, " urgent---> ");
                    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
                    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
                    strcat(address_string, "\n");
                    address_string[strlen(address_string) + 1] = 0;
                    address_string[strlen(address_string)] = connection->server.urgdata;
                    printf("%s", address_string);
                    return ;
                }
                if (connection->client.count_new_urg)
                {
                    printf("%s客户端接收到新的紧急数据!\n",name);
                    /*客户端接收到新的紧急数据 */
                    printf("--------------------------------\n");
                    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
                    strcat(address_string, " <--- urgent ");
                    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
                    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
                    strcat(address_string, "\n");
                    address_string[strlen(address_string) + 1] = 0;
                    address_string[strlen(address_string)] = connection->client.urgdata;
                    printf("%s", address_string);
                    return ;
                }
                if (connection->client.count_new)
                {
                    if (connection->addr.dest == 110||connection->addr.dest == 995)
                    {
                        printf("%s客户端接收到新的数据!\n",name);
                        /*客户端接收到新的数据 */
                        hlf = &connection->client;
                        strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                        strcat(address_string, " <--- ");
                        strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
                        strcat(address_string, "\n");
                        printf("--------------------------------\n");
                        printf("%s", address_string);
                        memcpy(content, hlf->data, hlf->count_new);
                        content[hlf->count_new] = '\0';
                        if (strstr(strncpy(status_code, content, 4), "+OK"))
                            printf("操作成功\n");
                        if (strstr(strncpy(status_code, content, 4), "-ERR"))
                            printf("操作失败\n");
                        for (i = 0; i < hlf->count_new; i++)
                        {
                            printf("%s", char_to_ascii(content[i]));
                        }
                        printf("\n");
                        if (strstr(content, "\n\r.\n\r"))
                            printf("数据传输结束\n");
                    }

                    if (connection->addr.dest == 445)
                    {
                        /* SMTP客户端接收到新的数据 */
                        hlf = &connection->client;
                        strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                        strcat(address_string, " <--- ");
                        strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
                        strcat(address_string, "\n");
                        printf("--------------------------------\n");
                        printf("%s", address_string);
                        memcpy(content, hlf->data, hlf->count_new);
                        content[hlf->count_new] = '\0';
                        if (strstr(strncpy(status_code, content, 3), "221"))
                            printf("连接中止\n");
                        if (strstr(strncpy(status_code, content, 3), "250"))
                            printf("操作成功\n");
                        if (strstr(strncpy(status_code, content, 3), "220"))
                            printf("表示服务就绪\n");
                        if (strstr(strncpy(status_code, content, 3), "354"))
                            printf("开始邮件输入，以\".\"结束\n");
                        if (strstr(strncpy(status_code, content, 3), "334"))
                            printf("服务器响应验证\n");
                        if (strstr(strncpy(status_code, content, 3), "235"))
                            printf("认证成功可以发送邮件了\n");
                        for (i = 0; i < hlf->count_new; i++)
                        {
                            printf("%s", char_to_ascii(content[i]));
                        }
                        printf("\n");
                    }

                    if(connection->addr.dest==23)
                    {
                        /*Telnet客户端接收到新的数据*/
                        hlf=&connection->client;
                        strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                        sprintf(address_string+strlen(address_string),": %i",ip_and_port.source);
                        strcat(address_string,"<----");
                        strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string), ": %i",
                        ip_and_port.dest);
                        strcat(address_string,"\n");
                        printf("---------------------------\n");
                        printf("%s",address_string);
                        //输出telnet客户端收到的新的数据
                        memcpy(content,hlf->data,hlf->count_new);
                        content[hlf->count_new]='\0';
                        for(i=0;i<hlf->count_new;i++)
                        {
                            printf("%s",char_to_ascii(content[i]));
                        }
                            printf("\n");
                    }

                    if(connection->addr.dest==80)
                    {
                        hlf=&connection->client;
                        strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                        sprintf(address_string+strlen(address_string),":%i",ip_and_port.source);
                        strcat(address_string,"<----");
                        strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string),":%i",ip_and_port.dest);
                        strcat(address_string,"\n");
                        printf("\n");
                        printf("%s",address_string);
                        printf("web accept state..\n");
                        printf("\n");
                        memcpy(content,hlf->data,hlf->count_new);
                        content[hlf->count_new]='\0';
                        parse_client_data(content,(u_int)hlf->count_new);
                    }

                    if(connection->addr.dest==443)
                    {
                        hlf=&connection->client;
                        strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                        sprintf(address_string+strlen(address_string),":%i",ip_and_port.source);
                        strcat(address_string,"<----");
                        strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string),":%i",ip_and_port.dest);
                        strcat(address_string,"\n");
                        printf("\n");
                        printf("%s",address_string);
                        printf("web accept state..\n");
                        printf("\n");
                        memcpy(content,hlf->data,hlf->count_new);
                        content[hlf->count_new]='\0';
                        parse_client_dataS(content,hlf->count_new);
                    }

                    if ((connection->addr.dest ==21)||(connection->addr.source ==20))
                    {
                        /* ftp客户端接收到新的数据 */
                        hlf = &connection->client;
                        strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                        strcat(address_string, " <--- ");
                        strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
                        strcat(address_string, "\n");
                        printf("--------------------------------\n");
                        printf("%s", address_string);
                        memcpy(content, hlf->data, hlf->count_new);
                        content[hlf->count_new] = '\0';
                        if(connection->addr.source ==20)
                        {
                            printf("传输的数据为：\n");
                            for (i = 0; i < hlf->count_new; i++)
                            {
                            printf("%s", char_to_ascii(content[i]));
                            }printf("\n");
                        }
                        else
                        {
                            if(content[0]=='1'||content[0]=='2'||content[0]=='3'||content[0]=='4'||content[0]=='5')
                                printf("ftp服务器响应状态代码为：%c%c%c\n",content[0],content[1],content[2] );
                            if(strncmp(content,"110",3)==0)
                                printf("新文件指示器上的重启标记\n");
                            if(strncmp(content,"120",3)==0)
                                printf("服务器准备就绪的时间（分钟数）\n");
                            if(strncmp(content,"125",3)==0)
                                printf("打开数据连接，开始传输\n");
                            if(strncmp(content,"150",3)==0)
                                printf("打开连接\n");
                            if(strncmp(content,"200",3)==0)
                                printf("成功\n");
                            if(strncmp(content,"202",3)==0)
                                printf("命令没有执行\n");
                            if(strncmp(content,"211",3)==0)
                                printf("系统状态回复\n");
                            if(strncmp(content,"212",3)==0)
                                printf("目录状态回复\n");
                            if(strncmp(content,"213",3)==0)
                                printf("文件状态回复\n");
                            if(strncmp(content,"214",3)==0)
                                printf("帮助信息回复\n");
                            if(strncmp(content,"215",3)==0)
                                printf("系统类型回复\n");
                            if(strncmp(content,"220",3)==0)
                                printf("服务就绪\n");
                            if(strncmp(content,"221",3)==0)
                                printf("退出网络\n");
                            if(strncmp(content,"225",3)==0)
                                printf("打开数据连接\n");
                            if(strncmp(content,"226",3)==0)
                                printf("结束数据连接\n");
                            if(strncmp(content,"227",3)==0)
                                printf("进入被动模式（IP\n");
                            if(strncmp(content,"地址、ID",3)==0)
                                printf("端口）\n");
                            if(strncmp(content,"230",3)==0)
                                printf("登录因特网\n");
                            if(strncmp(content,"250",3)==0)
                                printf("文件行为完成\n");
                            if(strncmp(content,"257",3)==0)
                                printf("路径名建立\n");
                            if(strncmp(content,"331",3)==0)
                                printf("要求密码\n");
                            if(strncmp(content,"332",3)==0)
                                printf("要求帐号\n");
                            if(strncmp(content,"350",3)==0)
                                printf("文件行为暂停\n");
                            if(strncmp(content,"421",3)==0)
                                printf("服务关闭\n");
                            if(strncmp(content,"425",3)==0)
                                printf("无法打开数据连接\n");
                            if(strncmp(content,"426",3)==0)
                                printf("结束连接\n");
                            if(strncmp(content,"450",3)==0)
                                printf("文件不可用\n");
                            if(strncmp(content,"451",3)==0)
                                printf("遇到本地错误\n");
                            if(strncmp(content,"452",3)==0)
                                printf("磁盘空间不足\n");
                            if(strncmp(content,"500",3)==0)
                                printf("无效命令\n");
                            if(strncmp(content,"501",3)==0)
                                printf("错误参数\n");
                            if(strncmp(content,"502",3)==0)
                                printf("命令没有执行\n");
                            if(strncmp(content,"503",3)==0)
                                printf("错误指令序列\n");
                            if(strncmp(content,"504",3)==0)
                                printf("无效命令参数\n");
                            if(strncmp(content,"530",3)==0)
                                printf("未登录网络\n");
                            if(strncmp(content,"532",3)==0)
                                printf("存储文件需要帐号\n");
                            if(strncmp(content,"550",3)==0)
                                printf("文件不可用\n");
                            if(strncmp(content,"551",3)==0)
                                printf("不知道的页类型\n");
                            if(strncmp(content,"552",3)==0)
                                printf("超过存储分配\n");
                            if(strncmp(content,"553",3)==0)
                                printf("文件名不允许\n");
                            for (i = 0; i < hlf->count_new; i++)
                            {
                                printf("%s", char_to_ascii(content[i]));
                            }
                            printf("\n");
                        }
                    }

                }
                else
                {
                    if (connection->addr.dest == 110||connection->addr.dest == 995)
                    {
                        printf("%s服务器接收到新的数据!\n",name);
                        /* 服务器接收到新的数据 */
                        hlf = &connection->server;
                        strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                        strcat(address_string, " ---> ");
                        strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
                        strcat(address_string, "\n");
                        printf("--------------------------------\n");
                        printf("%s", address_string);
                        memcpy(content, hlf->data, hlf->count_new);
                        content[hlf->count_new] = '\0';
                        if (strstr(content, "USER"))
                            printf("邮件用户名为\n");
                        if (strstr(content, "PASS"))
                            printf("用户密码为\n");
                        if (strstr(content, "STAT"))
                            printf("返回统计资料\n");
                        if (strstr(content, "LIST"))
                            printf("返回邮件数量和大小\n");
                        if (strstr(content, "RETR"))
                            printf("获取邮件\n");
                        if (strstr(content, "DELE"))
                            printf("删除邮件\n");
                        if (strstr(content, "QUIT"))
                            printf("退出连接\n");
                        for (i = 0; i < hlf->count_new; i++)
                        {
                            printf("%s", char_to_ascii(content[i]));
                        }
                        printf("\n");
                    }

                    if (connection->addr.dest == 445)
                    {
                        /* SMTP服务器接收到新的数据 */
                        hlf = &connection->server;
                        strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                        strcat(address_string, " ---> ");
                        strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
                        strcat(address_string, "\n");
                        printf("--------------------------------\n");
                        printf("%s", address_string);
                        memcpy(content, hlf->data, hlf->count_new);
                        content[hlf->count_new] = '\0';
                        if (strstr(content, "EHLO"))
                            printf("HELLO命令\n");
                        if (strstr(content, "QUIT"))
                            printf("退出连接\n");
                        if (strstr(content, "DATA"))
                            printf("开始传输数据\n");
                        if (strstr(content, "MAIL FROM"))
                            printf("发送方邮件地址为\n");
                        if (strstr(content, "RCPT TO"))
                            printf("接收方邮件地址为\n");
                        if (strstr(content, "AUTH"))
                            printf("请求认证\n");
                        if (strstr(content, "LOGIN"))
                            printf("认证机制为LOGIN\n");
                        for (i = 0; i < hlf->count_new; i++)
                        {
                            printf("%s", char_to_ascii(content[i]));
                        }
                        printf("\n");
                        if (strstr(content, "\n."))
                            printf("数据传输结束\n");
                    }

                    if(connection->addr.dest==23)
                    {
                        //telnet服务器接收到新的数据
                        hlf=&connection->server;
                        strcpy(address_string,   inet_ntoa(*((struct   in_addr*)
                        &(ip_and_port.saddr))));
                        sprintf(address_string + strlen(address_string), ":%i",
                        ip_and_port.source);
                        strcat(address_string,"--->");
                        strcat(address_string, inet_ntoa(*((struct  in_addr*)
                        &(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string),":%i",
                        ip_and_port.dest);
                        strcat(address_string,"\n");
                        printf("------------------------------");
                        printf("%s",address_string);
                        //输出telnet服务器接收到的新的数据
                        memcpy(content, hlf->data,hlf->count_new);
                        content[hlf->count_new]='\0';
                        for(i=0;i<hlf->count_new;i++)
                        {
                            printf("%s",char_to_ascii(content[i]));
                        }
                        printf("\n");
                    }

                    if(connection->addr.dest==80)
                    {
                        hlf=&connection->server;
                        strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                        sprintf(address_string+strlen(address_string),":%i",ip_and_port.source);
                        strcat(address_string,"---->");
                        strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                        sprintf(address_string+strlen(address_string),":%i",ip_and_port.dest);
                        strcat(address_string,"\n");
                        printf("\n");
                        printf("%s",address_string);
                        printf("web apache accept....\n");
                        printf("\n");
                        memcpy(content,hlf->data,hlf->count_new);
                        content[hlf->count_new]='\0';
                        parse_server_data(content,(u_int)hlf->count_new);
                    }

                    if(connection->addr.dest == 443)
                    {
                        hlf=&connection->server;
                        strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                        sprintf(address_string+strlen(address_string),":%i",ip_and_port.source);
                        strcat(address_string,"---->");
                        strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                        sprintf(address_string+strlen(address_string),":%i",ip_and_port.dest);
                        strcat(address_string,"\n");
                        printf("\n");
                        printf("%s",address_string);
                        printf("web apache accept....\n");
                        printf("\n");
                        memcpy(content,hlf->data,hlf->count_new);
                        /*void *memcpy(void *dest, const void *src, size_t n);*/
                        content[hlf->count_new]='\0';
                        parse_server_dataS(content,hlf->count_new);
                    }


                    if ((connection->addr.dest ==21)||(connection->addr.source ==20))
                    {
                        /* ftp服务器接收到新的数据 */
                        hlf = &connection->server;
                        strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                        strcat(address_string, " ---> ");
                        strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
                        sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
                        strcat(address_string, "\n");
                        printf("--------------------------------\n");
                        printf("%s", address_string);
                        memcpy(content, hlf->data, hlf->count_new);
                        content[hlf->count_new] = '\0';
                        if(connection->addr.source ==20)
                        printf("%sftp客户端与ftp服务器建立连接\n", address_string);
                        else
                        {
                            if (strstr(content, "ABOR"))
                                printf("中断数据连接程序: %s\n",content + strlen("ABOR"));
                            else if (strstr(content, "ACCT"))
                                printf("系统特权帐号: %s\n",content + strlen("ACCT"));
                            else if (strstr(content, "ALLO"))
                                printf("为服务器上的文件存储器分配字节: %s\n",content + strlen("ALLO"));
                            else if (strstr(content, "APPE"))
                                printf("添加文件到服务器同名文件: %s\n",content + strlen("APPE"));
                            else if (strstr(content, "CDUP"))
                                printf("改变服务器上的父目录: %s\n",content + strlen("CDUP"));
                            else if (strstr(content, "CWD"))
                                printf("改变服务器上的工作目录: %s\n",content + strlen("CWD"));
                            else if (strstr(content, "DELE"))
                                printf("删除服务器上的指定文件: %s\n",content + strlen("DELE"));
                            else if (strstr(content, "HELP"))
                                printf("返回指定命令信息: %s\n",content + strlen("HELP"));
                            else if (strstr(content, "LIST"))
                                printf("如果是文件名列出文件信息，如果是目录则列出文件列表: %s\n",content + strlen("LIST"));
                            else if (strstr(content, "MODE"))
                                printf("传输模式（S=流模式，B=块模式，C=压缩模式）: %s\n",content + strlen("MODE"));
                            else if (strstr(content, "MKD"))
                                printf("在服务器上建立指定目录: %s\n",content + strlen("MKD"));
                            else if (strstr(content, "NLST"))
                                printf("列出指定目录内容: %s\n",content + strlen("NLST"));
                            else if (strstr(content, "NOOP"))
                                printf("无动作，除了来自服务器上的承认: %s\n",content + strlen("NOOP"));
                            else if (strstr(content, "PASS"))
                                printf("系统登录密码: %s\n",content + strlen("PASS"));
                            else if (strstr(content, "PASV"))
                                printf("请求服务器等待数据连接: %s\n",content + strlen("PASV"));
                            else if (strstr(content, "PORT"))
                                printf("IP地址和两字节的端口ID: %s\n",content + strlen("PORT"));
                            else if (strstr(content, "PWD"))
                                printf("显示当前工作目录: %s\n",content + strlen("PWD"));
                            else if (strstr(content, "QUIT"))
                                printf("从FTP服务器上退出登录: %s\n",content + strlen("QUIT"));
                            else if (strstr(content, "REIN"))
                                printf("重新初始化登录状态连接: %s\n",content + strlen("REIN"));
                            else if (strstr(content, "REST"))
                                printf("由特定偏移量重启文件传递: %s\n",content + strlen("REST"));
                            else if (strstr(content, "RETR"))
                                printf("从服务器上找回（复制）文件: %s\n",content + strlen("RETR"));
                            else if (strstr(content, "RMD"))
                                printf("在服务器上删除指定目录: %s\n",content + strlen("RMD"));
                            else if (strstr(content, "RNFR"))
                                printf("对旧路径重命名: %s\n",content + strlen("RNFR"));
                            else if (strstr(content, "RNTO"))
                                printf("对新路径重命名:  %s\n",content + strlen("RNTO"));
                            else if (strstr(content, "SITE"))
                                printf("由服务器提供的站点特殊参数: %s\n",content + strlen("SITE"));
                            else if (strstr(content, "SMNT"))
                                printf("挂载指定文件结构: %s\n",content + strlen("SMNT"));
                            else if (strstr(content, "STAT"))
                                printf("在当前程序或目录上返回信息: %s\n",content + strlen("STAT"));
                            else if (strstr(content, "STOR"))
                                printf("储存（复制）文件到服务器上: %s\n",content + strlen("STOR"));
                            else if (strstr(content, "STOU"))
                                printf("储存文件到服务器名称上: %s\n",content + strlen("STOU"));
                            else if (strstr(content, "STRU"))
                                printf("数据结构（F=文件，R=记录，P=页面）: %s\n",content + strlen("STRU"));
                            else if (strstr(content, "SYST"))
                                printf("返回服务器使用的操作系统: %s\n",content + strlen("SYST"));
                            else if (strstr(content, "TYPE"))
                                printf("数据类型（A=ASCII，E=EBCDIC，I=binary）: %s\n",content + strlen("TYPE"));
                            else if (strstr(content, "USER"))
                                printf("系统登录的用户名: %s\n",content + strlen("USER"));
                            else
                                printf("ftp客户端使用命令为：%c%c%c%c\n",content[0],content[1],content[2],content[3] );
                        }
                        for (i = 0; i < hlf->count_new; i++)
                        {
                            printf("%s", char_to_ascii(content[i]));
                        }
                        printf("\n");
                    }

                }
            }
        default:
            break;
    }
    number++;
    if(number==Pnumber)
    {
        number=0;
        return;
    }

}

int HighProtocol()
{
    //设置网络接口
    //nids_params.device = "eth0";
       struct nids_chksum_ctl tmp;
    // printf("nids_chksum_ctl:%d\n",tmp.action);

    //关闭数据校验
         tmp.netaddr = 0;
         tmp.mask = 0;
         tmp.action = 1;
         nids_register_chksum_ctl(&tmp, 1);
    //printf("nids_chksum_ctl:%d\n",tmp.action);
    if (!nids_init())
     /* Libnids初始化 */
    {
        printf("0\n");
        printf("出现错误：%s\n", nids_errbuf);
        exit(1);
    }
    nids_register_tcp((void*)high_protocol_callback);
    /* 注册回调函数 */
    nids_run();
    /* Libnids进入循环捕获数据包状态 */
    return 0;
}

int main()
{
    int start;
    start=1;
    printf("Readly?\n");
    while(start!=0)
    {
        printf("请输入要捕获的数据包数量(注：（1）请输入整数 （2）-1代表无限制 （3）任何小于1的数默认为-1：");
        scanf("%d",&Pnumber);
        HighProtocol();
        printf("是否继续捕获数据包？（0-离开 1-继续）");
        scanf("%d",&start);
        fflush(stdin);
    }

}
