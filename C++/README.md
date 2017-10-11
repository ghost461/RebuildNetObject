# Part of C++
- 需要clang环境
- 使用make命令编译
- sudo ./test执行测试程序
- 编译过程可以自行查看makefile文件
#更新0.01Beta版本
- CLI程序，无界面
- 参数仅支持：-n, -p, -h, -v
- 可指定程序抓包数量及特定协议
- 示例：sudo ./test -n 10 -p tcp
- 示例：sudo ./test -v
- 示例：sudo ./test -h
