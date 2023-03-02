# lsocks5 c++ libuv

# 一款通过libuv实现的socks代理 


* 项目解决LOL 13.2 除Wegame进程与游戏进程以外进程无法调用拳头LCUapi开发



* 打开Wegame发现他可以正常使用，怀疑腾讯验证了文件证书(EasyAntiCheat就是效验证书，这是经验)，加上腾讯证书还是不行，后续测试加上腾讯白名单名称就可以了

* 开发socks5原因是有很多软件对接起来，测试更加方便，无需改动太多已有代码，后续国服无法使用，只需程序解决白名单问题即可

* socks5代理支持所有开发语言，只需自行搜索socks proxy代理 

* 支持socks5浏览器 firefox
 
* 另外发现腾讯都没有用WinVerifyTrust等函数测试证书有效性(大厂不应该这么不严谨)


* 以下是curl的测试代码,游戏参数自行替换  
· curl 命令行解释  -k https支持 -i 输出协议头 -X 请求协议 -u Authentication -H Resquest 协议头 -x 通过代理 -0 http 1.1  默认拳头api是http 2

```
curl -k -i -X GET -u riot:****  -H "Content-Type: application/json" -H  "Accept: */*" -x socks5h://127.0.0.1:9088 https://127.0.0.1:10187/lol-summoner/v1/current-summoner -0
```



