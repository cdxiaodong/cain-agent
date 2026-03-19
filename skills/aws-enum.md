---
name: aws-enum
type: enum
category: reconnaissance
platform: aws
severity: medium
---

# AWS 资源枚举技能

## 触发条件

- 获取到 AWS 凭证
- 用户要求"枚举 AWS 资源"
- 用户要求"列出所有资源"

## 枚举流程

```bash
# 1. 验证凭证
aws sts get-caller-identity
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# 2. 枚举所有区域
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

# 3. 在每个区域枚举资源
for region in $REGIONS; do
    echo "=== Region: $region ==="

    # EC2 实例
    aws ec2 describe-instances --region $region --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null

    # Lambda 函数
    aws lambda list-functions --region $region --query 'Functions[].FunctionName' --output text 2>/dev/null

    # RDS 实例
    aws rds describe-db-instances --region $region --query 'DBInstances[].DBInstanceIdentifier' --output text 2>/dev/null

    # S3 存储桶（全局）
    # aws s3 ls
done
```

## 完整枚举脚本

```bash
#!/bin/bash
# AWS 资源完整枚举

echo "=== AWS 账户信息 ==="
aws sts get-caller-identity

echo -e "\n=== IAM 用户 ==="
aws iam list-users --query 'Users[].UserName' --output text

echo -e "\n=== IAM 角色 ==="
aws iam list-roles --query 'Roles[].RoleName' --output text

echo -e "\n=== S3 存储桶 ==="
aws s3 ls

echo -e "\n=== EC2 实例 ==="
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,Type:InstanceType,State:State.Name}' --output table

echo -e "\n=== Lambda 函数 ==="
aws lambda list-functions --query 'Functions[].{Name:FunctionName,Runtime:Runtime}' --output table

echo -e "\n=== RDS 实例 ==="
aws rds describe-db-instances --query 'DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,Status:DBInstanceStatus}' --output table

echo -e "\n=== CloudFormation 堆栈 ==="
aws cloudformation describe-stacks --query 'Stacks[].{Name:StackName,Status:StackStatus}' --output table

echo -e "\n=== VPC ==="
aws ec2 describe-vpcs --query 'Vpcs[].{VpcId:VpcId,Cidr:CidrBlock}' --output table

echo -e "\n=== EKS 集群 ==="
aws eks list-clusters --query 'clusters' --output text

echo -e "\n=== ECS 集群 ==="
aws ecs list-clusters --query 'clusterArns' --output text
```

## 输出报告

```markdown
# AWS 资源枚举报告
- Account ID: 123456789012
- IAM 用户: X 个
- IAM 角色: Y 个
- S3 存储桶: Z 个
- EC2 实例: N 个
- Lambda 函数: M 个
- RDS 实例: K 个
```

## 下一步

1. aws-iam-attack - 尝试权限提升
2. aws-s3-attack - 攻击存储桶
3. aws-lambda-attack - 攻击函数
