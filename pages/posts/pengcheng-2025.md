---
title: 鹏城杯2025
date: 2025-12-13
categories:
  - CTF
tags:
  - 鹏城杯2025
  - misc
---

# 鹏城杯2025

## misc

### **pcb5-blue**

![image-20251213104718704](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213104718704.png)

先去用stegsolve看看，发现应该是msb隐写

![image-20251213104810118](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213104810118.png)

![image-20251213104824746](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213104824746.png)

然后用bkcrack爆一下

![image-20251213180216627](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213180216627.png)

png_header就是png头

![image-20251213180331572](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213180331572.png)

![image-20251213180516996](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213180516996.png)

发现解压出来的图片尾部又有一个图片

![image-20251213180752516](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213180752516.png)

明显的蓝条

两张图结合一下，双图盲水印

![image-20251213181922621](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213181922621.png)

![image-20251213181945736](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213181945736.png)

最后得到flag{a5e2ffeb-133e-4eb0-9855-d4d0078326ee}

### **pcb5-time**

![image-20251213112413528](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213112413528.png)

反编译一下，发现核心逻辑是一个**限时答题 + 随机图片 Base64 校验**的程序，程序从 `./png` 目录随机选取 **12个文件**，将其内容 **Base64 编码后输出**，要求你在 **2 秒内输入文件名中提取出的数字**；
 **连续答对 12 次后，直接给你一个 `system(buf)` 的命令执行入口**

![image-20251213112540105](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213112540105.png)

写个脚本看看传了什么

![image-20251213112621910](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213112621910.png)

发现是一张压缩过的png

发现他就是一个普通的时钟，多来几次把十二个都拉下来

![image-20251213183213106](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251213183213106.png)