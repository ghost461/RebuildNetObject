# Part of C++
- 需要clang环境
- 使用make命令编译
- sudo ./test执行测试程序
- 编译过程可以自行查看makefile文件
# 更新0.01Beta版本
- CLI程序，无界面
- 参数仅支持：-n, -p, -h, -v
- 可指定程序抓包数量及特定协议
- 示例：sudo ./analysisTool -n 10 -p tcp
- 示例：sudo ./analysisTool -v
- 示例：sudo ./analysisTool -h
# Add new function for C++
- Application layer protocol support
- Parameter "-A"
- Support: POP3 & SMTP & TELNET & FTP & HTTP & HTTPS
- sudo ./analysisTool -A
- Need chinese system
- Coding in UTF-8
