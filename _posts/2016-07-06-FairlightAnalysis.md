---
layout: post
title: CTF例题分析－Fairlight
date:   2016-07-05 10:00:00
categories: CTF分析
---

## Fairlight手工分析

### 1. 题目

A simple reverse me that takes a key as a command line argument and checks it against 14 checks. Possible to solve the challenge using angr without reversing any of the checks.



### 2. main函数分析

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



