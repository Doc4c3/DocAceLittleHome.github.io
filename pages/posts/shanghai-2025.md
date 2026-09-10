---
title: 第十届上海市大学生网络安全大赛WriteUp
date: 2025-08-06
categories:
  - CTF
tags:
  - 上海市赛
  - misc
---

# 第十届上海市大学生网络安全大赛WriteUp

## MISC

### derderjia

上来先看来一下http报文，在最后一个包发现了server_key.txt的内容

![屏幕截图 2025-08-06 101854](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 101854.png)

![屏幕截图 2025-08-06 092237](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 092237.png)

![屏幕截图 2025-08-06 102101](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 102101.png)

配置好了发现上传的是一个压缩包，有密码，看了看pcapng的文件注释发现在dns里有线索

![屏幕截图 2025-08-06 101553](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 101553.png)

![屏幕截图 2025-08-06 100708](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 100708.png)

![屏幕截图 2025-08-06 102320](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 102320.png)

找到压缩包密码PanShi2025

解压得到一只马的图片，发现他的高被修改过，改回来得到flag

![屏幕截图 2025-08-06 102544](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 102544.png)

![屏幕截图 2025-08-06 101428](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 101428.png)

### 两个数字

先是一串二进制

![屏幕截图 2025-08-06 113548](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 113548.png)

![屏幕截图 2025-08-06 113526](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 113526.png)

看注释提示8bit，那就试试先reverse再补到八位，再转ascii

```python
def reverse_binary_strings_and_pad(binary_string):
    # 首先，将字符串按空格分割成多个二进制串
    binary_list = binary_string.split()

    # 初始化一个空列表来存储反转后的二进制串
    reversed_and_padded_list = []

    # 遍历每个二进制串
    for binary in binary_list:
        # 反转二进制串
        reversed_binary = binary[::-1]
        # 在高位补零，补至8位
        padded_binary = reversed_binary.zfill(8)
        reversed_and_padded_list.append(padded_binary)

    return reversed_and_padded_list

def binary_list_to_ascii(binary_list):
    # 初始化一个空字符串来存储ASCII字符
    ascii_string = ""
    # 遍历每个8位二进制串
    for binary in binary_list:
        # 将二进制串转换为整数
        decimal_value = int(binary, 2)
        # 将整数转换为ASCII字符并添加到结果字符串中
        ascii_string += chr(decimal_value)
    return ascii_string

# 给定的二进制字符串
binary_string = "1100001 000011 0111011 1110011 0100111 001011 0010111 1010111 100011 1000011 0010111 1001011 1111011 0111011 100001 100001 1001101 000011 1010111 1111101 0001011 1000011 0110111 110011 1111101 0000111 1000011 1100111 1100111 1010011 0010011 1111101 0010111 0001011 110011 1111101 0110011 1001011 0100111 1100111 0010111 1111101 0011011 110011 0110111 1010011 100011 100001 100001"

# 调用函数并打印结果
reversed_and_padded_list = reverse_binary_strings_and_pad(binary_string)
ascii_string = binary_list_to_ascii(reversed_and_padded_list)
print(ascii_string)

```

![屏幕截图 2025-08-06 113537](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 113537.png)

得到密码C0ngr4tu1ation!!Y0u_hav3_passed_th3_first_l3ve1!!

![屏幕截图 2025-08-06 114147](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 114147.png)

![屏幕截图 2025-08-06 114224](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 114224.png)

格雷码，

### easy_misc

先拿到一个残缺的二维码，想着去补全

![屏幕截图 2025-08-06 141248](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 141248.png)

![屏幕截图 2025-08-06 142330](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 142330.png)

![87fa1e7675cf88f9b93434fff86853c0](C:\Users\12558\xwechat_files\wxid_f4iiuevbfelp22_9271\temp\RWTemp\2025-08\9e20f478899dc29eb19741386f9343c8\87fa1e7675cf88f9b93434fff86853c0.jpg)

cao，被骗了，010看看，发现了有个压缩包在末尾

![屏幕截图 2025-08-06 142520](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 142520.png)

解压得到了一个Ook brainfuck

```
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook. Ook? Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook?
Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook!
Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook!
Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook? Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook?
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook.
Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook? Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook?
Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook!
Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook.
Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook. Ook! Ook. Ook! Ook. Ook?
Ook.
```

解密得到

![屏幕截图 2025-08-06 143030](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 143030.png)

```
y0u_c@t_m3!!!
```

直接去试试flag的压缩包

得到flag

![屏幕截图 2025-08-06 143622](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-08-06 143622.png)