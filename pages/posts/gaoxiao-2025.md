---
title: 2025高校网络安全管理运维赛
date: 2025-10-20
categories:
  - CTF
tags:
  - 高校赛
  - forensics
---

# 2025高校网络安全管理运维赛

## 电子数据取证分析师赛道

### 电子数据分析-aipowah（检材04）

#### flag 1：

要知道服务器rootfs采用的文件系统格式，就去etc/下的fstab里面看

![image-20251020202910742](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020202910742.png)

发现是xfs，提交flag，成功

#### flag 2：

AI诈骗站点的域名，直接看火眼的分析界面的Nginx服务器栏

![image-20251020203104348](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020203104348.png)

发现是y8fmin.wf941021.org

#### flag 3：

无

#### flag4：

找诈骗聊天的AI模型，就去docker里面找，可以知道**容器内的 `.env` 文件**：在 `/app/` 或应用工作目录，就搜索app，一个一个翻，找到了一个app.py其中就有从siliconflow调用的代码

```python
class AIClient:    def __init__(self, url, cred):        self.url = url        self.cred = cred    def chat(self, history: list[dict[str, str]], message: str) -> str:        messages = history.copy()        messages.append({"role": "user", "content": message})        payload = {            "model": "Qwen/Qwen3-30B-A3B-Instruct-2507",            "messages": messages,        }        headers = {            "Authorization": f"Bearer {self.cred}",            "Content-Type": "application/json",        }
```

![image-20251020203841930](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020203841930.png)

发现用的是Qwen3-30B-A3B-Instruct-2507

#### flag 5：

找操作系统日志外发的服务器IP地址，那就去检查系统中配置的日志转发服务记录，直接搜索rsyslog，然后一个一个看![image-20251020204151113](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020204151113.png)

最后发现日志外发服务器IP地址：**10.0.38.211**

#### flag 6：

开发人员调用AI模型服务所使用的密钥在flag4的那个app.py文件中有写

```python
with open("/app/.ak", "r") as f:    API_KEY = json.loads(f.read())["ak"]
```

那就知道**密钥文件**：`/app/.ak`

![image-20251020204706559](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020204706559.png)

得到密钥：an-m2h0xum6l59cgmx7hy3ctolligvkf

### 电子数据恢复-ARRAY（检材03）

#### flag 1：

![屏幕截图 2025-10-20 202101](C:\Users\12558\Pictures\Screenshots\屏幕截图 2025-10-20 202101.png)

根据分区表的信息推理其文件系统可能名为zfs

提交flag，通过

### 电子数据提取与固定-Fitness（检材01）

#### flag 1：

知道是在注册表拉出SAM和SYSTEM做mimikatz，但是工具坏了，遂失败

#### flag 2：

Linux环境很简单，先去找到berserker的用户，在他的user底下搜索appdata，找到了OpenSuse

![image-20251020205834672](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020205834672.png)

#### flag 3（疑问）：

去桌面把fit拉出来，丢到fit file viewer（[FIT File Viewer](https://www.fitfileviewer.com/)），自动修复

![image-20251020210123551](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020210123551.png)

下载之后改成一样的名字，cyberchef取个SM3值，提交flag发现不对，后面又试了几种改发，都没成功

![image-20251020210704301](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020210704301.png)

#### flag 4：

下载记录表格

![image-20251020210945786](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020210945786.png)

降序排列

![image-20251020211113530](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020211113530.png)

26.603m/s=95.7708km/s~=95.77km/s

![image-20251020211234225](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020211234225.png)

#### flag 5：

![image-20251020211332034](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020211332034.png)

该设备的制造商名称为 strava

### 电子数据提取与固定-Synology（检材02）

#### flag 1：

从浏览器中提取dsm的设备名，如图：![image-20251020212030107](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020212030107.png)

catdiskrecorder

#### flag 2：

从系统中提取群晖smb共享的密码，直接在火眼Linux基本信息的历史命令中找到![image-20251020213449395](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020213449395.png)

SMB_PASSWORD=6CzRWsUNYUpp

#### flag 3：

直接利用火眼创立时间线，时间排序，只看检材2-2群晖系统，发现三个主要时间段，1970，2018，2025。1970年的是出厂设置文件，2018年和2025年分别取一个最早时间，最后发现是2025年。

![image-20251020214055101](C:\Users\12558\AppData\Roaming\Typora\typora-user-images\image-20251020214055101.png)

2025-10-12 22:16