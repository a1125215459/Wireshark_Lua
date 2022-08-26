如何将lua文件应用至wireshark
1.编写好lua文件，如：test.lua
2.将文件移动至/usr/share/wireshark/目录下
3.修改/usr/share/wireshark/init.lua文件，在最后一行加入:
dofile(DATA_DIR.."test.lua")
4.打开wireshark，查看应用成功
