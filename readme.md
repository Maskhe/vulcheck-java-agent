![](./logo.png)
## 简介

通过Java插桩技术实现的漏洞检测工具。

## 使用方式

在启动JavaWeb应用程序时，通过添加 `-javaagent:[vulcheck-java-agent所在位置]` 启动参数即可。

## 支持检测的漏洞类型

- 命令执行
- SSRF
- 路径穿越
- Java反序列化
- JNDI注入
- SQL注入
- NoSQL注入
- HTTP请求头注入

- ......

## 检测能力

![](./漏洞证明.png)

上面是一处较深的命令执行漏洞案例，污点由source点开始经过了各种字符串变换（传播节点）最终流入到
Runtime.getRuntime().exec()方法

## todo
