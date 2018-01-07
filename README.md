# RebuildNetObject
## 重构网络协议分析程序
- C++部分根据C重构移植
- 需要PCAP环境
### 以下程序均使用wireshark检验过
- getmask_code.c已完成
- pcap_next_code.c已完成
- pcap_loop_code.c已完成
- get_ethernet1_code.c已完成
- get_ethernet2_code.c已完成
- get_arp_code.c已完成
- get_ip_code.c已完成
- get_icmp_code.c已完成
- get_tcp_code.c已完成
### C语言部分2017完成
- get_packet_code.c(数据包综合捕获程序)已完成
### C++部分开始
#### C++部分更新0.01Beta版本
- CLI程序，无界面
- 参数仅支持：-n, -p, -h, -v
- 可指定程序抓包数量及特定协议
- 示例：sudo ./analysisTool -n 10 -p tcp
- 示例：sudo ./analysisTool -v
- 示例：sudo ./analysisTool -h
### Add new function for C
- oicq Sniff
- print QQ number and IP address
- make
- make clean
- sudo ./QicqAnalyis
### Add new function for C++
- Application layer protocol support
- Parameter "-A"
- Support: POP3 & SMTP & TELNET & FTP & HTTP & HTTPS
- sudo ./analysisTool -A
- Need chinese system
- Coding in UTF-8
