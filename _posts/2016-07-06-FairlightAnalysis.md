---
layout: post
title: CTF例题分析－Fairlight
date:   2016-07-05 10:00:00
categories: CTF分析
---

## Fairlight手工分析

### 1. 题目

A simple reverse me that takes a key as a command line argument and checks it against 14 checks. Possible to solve the challenge using angr without reversing any of the checks.

### 2. 手工分析

#### 2.1 整体逻辑

![the whole logic](/static/img/whole_logic.png)



程序接受一个key作为参数，然后对key进行14次验证。若每次验证均通过，则认证成功；否则一旦某次验证失败，则调用denied_access，认证失败。



#### 2.2 main函数

main函数首先会验证key的长度，是否为14个字节。若是则进入check过程；若不是则调用denied_access退出程序。流程见下图：

![main](/static/img/main_len.png)



0x401995主要逻辑：将key参数所在地址传给rax，然后从rax向code变量所在地址处复制28h(即40)个字符（实际上只有前14个字符有意义）。之后便是14次验证函数，从check0到check13。



code变量：处于bss段，即未初始化的变量，如下图所示。由于共复制了14个有效字符，故code变量后的13个字节位置均被赋值，其中每个标记处即表示一个字节，与输入的key一一对应。这些值将会在各个check_n函数中使用到。

![code](/static/img/code.png)



#### 2.3 check_0函数

主要汇编代码：

![check_0](/static/img/check_0.png)



其中cs:code、cs:byte_6030BD等即为上述bss中的字节，与输入变量key对应。

每次check都要先取对应位置的字节（即check_n获取key中第n+1个字节），然后再获取key中其他位置的4、5个字符，进行一系列运算，生成最终两个值比较是否相等。若不相等，则调用denied_access退出程序；否则说明当前check通过，返回main函数，进行下一个check。

因此手工分析则需要对14个字节设置未知变量，然后按照14个check的逻辑编写限制条件，形成方程式，最终对其求解即可。

举例说明：对于check_0，设上图中五个位置变量依次为a、b、c、d、e，则最终式子为

```
a*(d+b^c)-0AB8 = e
```

另外13个check的也可按此写出，此处不再赘述。





### 3. angr分析

```
proj = angr.Project('./fairlight', load_options={"auto_load_libs": False})
argv1 = angr.claripy.BVS("argv1", 0xE * 8)
```
加载程序，并对输入变量进行符号化，即创建输入的符号化表达式。

由于输入是14个字节，则该符号表达式argv1的大小为14*8 bit。



```
initial_state = proj.factory.entry_state(args=["./fairlight", argv1])
```
因为angr符号执行二进制代码时主要操作对象为SimState，所以我们希望能创建一个符号程序状态。entry_state方法即会创建一个处于程序入口点的程序状态。

该程序执行时命令行格式为：./fairlight key

因此将["./fairlight", argv1]作为创建初始程序状态的参数args，从而生成initial_state。



```
initial_path = proj.factory.path(initial_state)
```
State是相对静态的对象，可以对其进行读写；想要真正进行符号执行，还需要有个Path。

Path中会包含states信息，是用户执行程序(step forward)、跟踪执行历史的接口。



```
path_group = proj.factory.path_group(initial_state)
```
PathGroup是paths的集合，对不同的path有不同的标签：active、deadended、found、avoided等，能从高层次来管理符号执行过程。



```
path_group.explore(find=0x4018f7, avoid=0x4018f9)
```
现在开始执行！

调用explore是符号执行的一种方法，可以通过添加一些限制（find参数指定要执行到的地址；avoid参数指定避免执行到的地址），来探索出符合这些限制的路径。

![explore](/static/img/explore.png)

上面find=0x4018f7，该地址是第14层验证函数中最后比较时，符合条件情况下执行的指令地址；

上面avoid=0x4018f9，该地址是第14层验证函数中最后比较时，不符合条件情况下执行的指令地址；

通过find和avoid的限制，最后找到的肯定是14层验证均通过的那条路径，即我们的输入和flag完全一致则验证成功的路径。

执行结果如下：

![result](/static/img/result.png)

确实找到了一条路径，也避免了一条路径，另有14条终止的路径（即输入长度不等于14则报错、前13次每次验证不通过则报错）。



```
found = path_group.found[0]
```
获取符合限制的那条路径



```
print found.state.se.any_str(argv1)
```
输出该条路径上符号表达式argv1的具体值，也就是我们要找的flag

![flag](/static/img/flag.png)