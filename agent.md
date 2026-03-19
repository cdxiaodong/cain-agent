# 云安全渗透测试 Agent - 技能管理系统

## 🎯 Agent 核心功能

这是一个**实战导向**的云安全渗透测试 Agent，能够自主执行攻击并管理所有技能文件。

---

## 📊 技能文件清单（实时更新）

### 实战攻击技能（54个）

#### AWS 平台（14个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `aws-iam-attack.md` | IAM 权限提升 | critical | ✅ |
| `aws-metadata-attack.md` | 元数据服务 SSRF | high | ✅ |
| `aws-s3-attack.md` | S3 数据窃取 | high | ✅ |
| `aws-lambda-attack.md` | Lambda 代码注入 | high | ✅ |
| `aws-ec2-attack.md` | EC2 实例攻击 | high | ✅ |
| `aws-rds-attack.md` | RDS 数据库攻击 | high | ✅ |
| `aws-secrets-attack.md` | Secrets 窃取 | critical | ✅ |
| `aws-enum.md` | 资源枚举 | medium | ✅ |
| `aws-persistence.md` | 持久化后门 | high | ✅ |
| `aws-cloudformation-attack.md` | IaC 后门注入 | high | ✅ |
| `aws-eks-attack.md` | Kubernetes 集群攻击 | critical | ✅ |
| `aws-ecs-attack.md` | 容器服务攻击 | high | ✅ |
| `aws-fargate-attack.md` | Serverless 容器攻击 | high | ✅ |
| `aws-cloudwatch-attack.md` | 监控日志利用 | medium | ✅ |
| `aws-apprunner-attack.md` | App Runner 攻击 | high | ✅ |

#### GCP 平台（4个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `gcp-attack.md` | GCP 综合攻击 | high | ✅ |
| `gcp-cloudfunctions-attack.md` | Cloud Functions 攻击 | high | ✅ |
| `gcp-storage-attack.md` | GCS 存储攻击 | high | ✅ |
| `gcp-bigquery-attack.md` | BigQuery 数据攻击 | high | ✅ |
| `gcp-compute-engine-attack.md` | GCE 实例攻击 | high | ✅ |

#### Azure 平台（3个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `azure-attack.md` | Azure 综合攻击 | high | ✅ |
| `azure-functions-attack.md` | Functions 攻击 | high | ✅ |
| `azure-devops-attack.md` | DevOps 攻击 | high | ✅ |
| `azure-keyvault-attack.md` | Key Vault 攻击 | critical | ✅ |

#### CI/CD 平台（9个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `jenkins-attack.md` | Jenkins 攻击 | high | ✅ |
| `gitlab-attack.md` | GitLab 攻击 | high | ✅ |
| `github-attack.md` | GitHub 攻击 | high | ✅ |
| `github-actions-attack.md` | GitHub Actions 攻击 | high | ✅ |
| `circleci-attack.md` | CircleCI 攻击 | high | ✅ |
| `concourse-attack.md` | Concourse 攻击 | high | ✅ |
| `bitbucket-attack.md` | Bitbucket 攻击 | high | ✅ |

#### 容器与编排（3个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `docker-attack.md` | 容器逃逸 | critical | ✅ |
| `kubernetes-attack.md` | K8s 攻击 | critical | ✅ |
| `harbor-attack.md` | 容器注册表攻击 | medium | ✅ |

#### 数据库平台（7个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `elasticsearch-attack.md` | 搜索引擎攻击 | critical | ✅ |
| `redis-attack.md` | 内存数据库攻击 | critical | ✅ |
| `mongodb-attack.md` | NoSQL 攻击 | high | ✅ |
| `cassandra-attack.md` | 分布式数据库攻击 | medium | ✅ |

#### 消息队列平台（2个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `kafka-attack.md` | Kafka 攻击 | high | ✅ |
| `rabbitmq-attack.md` | RabbitMQ 攻击 | high | ✅ |

#### DevSecOps 平台（1个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `sonarqube-attack.md` | 代码质量分析攻击 | medium | ✅ |

#### 服务网格与配置（2个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `consul-attack.md` | 服务发现攻击 | medium | ✅ |
| `vault-attack.md` | 密钥管理攻击 | critical | ✅ |

#### 其他平台（5个）

| 技能文件 | 攻击类型 | 严重程度 | 状态 |
|---------|---------|---------|------|
| `cloudflare-attack.md` | CDN 攻击 | medium | ✅ |
| `jira-attack.md` | 问题跟踪攻击 | medium | ✅ |
| `terraform-attack.md` | IaC 攻击 | high | ✅ |
| `nginx-attack.md` | Web 服务器攻击 | medium | ✅ |
| `active-directory-attack.md` | AD 域攻击 | critical | ✅ |
| `splunk-attack.md` | SIEM 攻击 | medium | ✅ |

**总计**: 53 个实战攻击技能

---

## 🤖 自动技能选择逻辑

### 输入解析器

```python
def parse_user_input(user_input: str) -> dict:
    """解析用户输入，提取关键信息"""

    # 平台识别
    platforms = {
        'AWS': ['aws', 'amazon', 's3', 'ec2', 'lambda'],
        'GCP': ['gcp', 'google cloud', 'gke', 'gcs'],
        'Azure': ['azure', 'microsoft', 'aad'],
        'Jenkins': ['jenkins', 'ci/cd'],
        'GitHub': ['github', 'actions'],
        'GitLab': ['gitlab'],
        'Docker': ['docker', 'container'],
        'Kubernetes': ['k8s', 'kubernetes', 'eks', 'gke']
    }

    # 攻击类型识别
    attack_types = {
        'privilege-escalation': ['权限提升', 'privesc', '提权', 'escalate'],
        'ssrf': ['ssrf', '元数据', 'metadata', 'internal'],
        'data-exfiltration': ['数据窃取', '下载', 'exfiltrate', 'dump'],
        'persistence': ['持久化', '后门', 'persistence', 'backdoor'],
        'enum': ['枚举', 'list', 'enum', 'discover']
    }

    # 识别平台
    detected_platform = None
    for platform, keywords in platforms.items():
        if any(kw in user_input.lower() for kw in keywords):
            detected_platform = platform
            break

    # 识别攻击类型
    detected_attack = None
    for attack, keywords in attack_types.items():
        if any(kw in user_input.lower() for kw in keywords):
            detected_attack = attack
            break

    # 识别资源类型
    resource_types = {
        'iam': 'iam-attack',
        'lambda': 'lambda-attack',
        'ec2': 'ec2-attack',
        's3': 's3-attack',
        'rds': 'rds-attack',
        'kubernetes': 'kubernetes-attack'
    }

    detected_resource = None
    for resource, skill in resource_types.items():
        if resource in user_input.lower():
            detected_resource = skill
            break

    return {
        'platform': detected_platform,
        'attack_type': detected_attack,
        'resource': detected_resource,
        'input': user_input
    }
```

### 技能匹配器

```python
def match_skill(parsed_input: dict) -> list:
    """根据解析结果匹配合适的技能"""

    matched_skills = []

    # 优先级 1: 直接资源匹配
    if parsed_input['resource']:
        skill_name = parsed_input['resource']
        if skill_exists(skill_name):
            matched_skills.append(skill_name)

    # 优先级 2: 平台 + 攻击类型匹配
    if parsed_input['platform'] and parsed_input['attack_type']:
        platform = parsed_input['platform'].lower()
        attack = parsed_input['attack_type']

        if platform == 'aws':
            if attack == 'privilege-escalation':
                matched_skills.append('aws-iam-attack')
            elif attack == 'ssrf':
                matched_skills.append('aws-metadata-attack')
            elif attack == 'data-exfiltration':
                matched_skills.append('aws-s3-attack')
            elif attack == 'enum':
                matched_skills.append('aws-enum')

        elif platform == 'gcp':
            matched_skills.append('gcp-attack')

        elif platform == 'jenkins':
            matched_skills.append('jenkins-attack')

        # ... 更多匹配规则

    # 优先级 3: 关键词模糊匹配
    matched_skills.extend(fuzzy_match_skills(parsed_input['input']))

    return matched_skills
```

---

## 🔄 技能激活流程

### 完整执行流程

```
用户输入
    ↓
输入解析器（parse_user_input）
    ↓
技能匹配器（match_skill）
    ↓
[生成技能列表]
    ↓
技能执行器（execute_skill）
    ├─ 加载技能文件
    ├─ 执行前置检查
    ├─ 选择攻击方法
    ├─ 执行攻击步骤
    ├─ 验证攻击结果
    └─ 生成攻击报告
    ↓
技能链分析器（suggest_next_skills）
    ↓
返回结果给用户
```

### 技能执行器实现

```python
def execute_skill(skill_name: str, context: dict):
    """执行单个技能"""

    # 1. 加载技能文件
    skill_file = f"/private/tmp/cloud-pentest-framework/skills/{skill_name}.md"
    with open(skill_file, 'r') as f:
        skill_content = f.read()

    # 2. 解析技能元数据
    metadata = parse_skill_metadata(skill_content)

    # 3. 执行前置检查
    print(f"🔍 执行前置检查: {skill_name}")
    if not run_pre_checks(skill_content, context):
        print("❌ 前置检查失败")
        return False

    # 4. 选择攻击方法
    available_methods = extract_attack_methods(skill_content)
    selected_method = select_best_method(available_methods, context)

    print(f"🎯 选择攻击方法: {selected_method}")

    # 5. 执行攻击步骤
    print("⚡ 执行攻击...")
    result = execute_attack_steps(skill_content, selected_method, context)

    # 6. 验证结果
    if verify_attack_result(skill_content, result):
        print("✅ 攻击成功!")

        # 7. 生成报告
        report = generate_attack_report(skill_content, result)
        print(report)

        # 8. 建议下一步
        next_skills = suggest_next_skills(skill_name, context)
        if next_skills:
            print(f"\n📌 建议下一步技能: {', '.join(next_skills)}")

        return True
    else:
        print("❌ 攻击失败")
        # 尝试错误处理
        handle_attack_failure(skill_content, result)
        return False
```

---

## 🧠 技能组合策略

### 攻击链模板

```python
# 预定义的攻击链模板
ATTACK_CHAINS = {
    'aws-full-compromise': [
        'aws-enum',           # 1. 枚举资源
        'aws-iam-attack',      # 2. 权限提升
        'aws-metadata-attack', # 3. 元数据服务
        'aws-s3-attack',       # 4. 数据窃取
        'aws-persistence'      # 5. 持久化
    ],

    'ci-cd-supply-chain': [
        'github-enum',
        'github-actions-attack',
        'github-attack',
        'gitlab-attack'
    ],

    'container-escape': [
        'docker-attack',
        'kubernetes-attack',
        'aws-ec2-attack'
    ],

    'cloud-platform': {
        'aws': ['aws-enum', 'aws-iam-attack', 'aws-s3-attack'],
        'gcp': ['gcp-attack'],
        'azure': ['azure-attack']
    }
}
```

### 智能技能组合

```python
def suggest_attack_chain(user_goal: str, current_context: dict) -> list:
    """根据用户目标和当前上下文建议攻击链"""

    # 分析用户目标
    if '完全控制' in user_goal or '接管' in user_goal:
        return ATTACK_CHAINS['aws-full-compromise']

    elif '供应链' in user_goal or 'ci/cd' in user_goal:
        return ATTACK_CHAINS['ci-cd-supply-chain']

    elif '容器' in user_goal or '逃逸' in user_goal:
        return ATTACK_CHAINS['container-escape']

    elif '数据' in user_goal or '窃取' in user_goal:
        # 数据窃取攻击链
        if current_context.get('platform') == 'aws':
            return ['aws-enum', 'aws-s3-attack', 'aws-secrets-attack']

    # 默认返回枚举技能
    return ['aws-enum']
```

---

## 📋 技能执行示例

### 示例 1: AWS 凭证渗透

```
用户: 我有一个 AWS Access Key: AKIAIOSFODNN7EXAMPLE

Agent:
[输入解析]
- 平台: AWS
- 攻击类型: privilege-escalation
- 资源: 未指定

[技能匹配]
→ 匹配技能: aws-iam-attack

[技能执行]
🔍 执行前置检查: aws-iam-attack
✅ 凭证有效

🎯 选择攻击方法: iam:CreateAccessKey
⚡ 执行攻击...
[执行步骤]
1. 枚举用户权限
2. 发现高权限用户: admin-user
3. 为 admin-user 创建访问密钥
4. 验证新凭证权限

✅ 攻击成功!

[生成报告]
# AWS IAM 攻击报告
- 目标账户: 123456789012
- 攻击方法: iam:CreateAccessKey
- 获取权限: AdministratorAccess
- 影响: 完全控制账户

📌 建议下一步技能: aws-enum, aws-s3-attack, aws-persistence
```

### 示例 2: SSRF 漏洞利用

```
用户: 发现一个 SSRF 漏洞

Agent:
[输入解析]
- 攻击类型: ssrf
- 平台: 未指定（可能是 AWS）

[技能匹配]
→ 匹配技能: aws-metadata-attack

[技能执行]
🔍 执行前置检查: aws-metadata-attack
⚡ 测试元数据服务访问...

🎯 选择攻击方法: 方法 1 - 直接访问（IMDSv1）
⚡ 执行攻击...
1. 获取 IAM 角色: role-name
2. 获取临时凭证
3. 验证凭证权限

✅ 攻击成功!

📌 建议下一步技能: aws-iam-attack, aws-s3-attack
```

---

## 🎓 技能学习模式

### 技能索引更新

```python
def update_skill_index():
    """扫描 skills 目录并更新技能索引"""

    skills_dir = "/private/tmp/cloud-pentest-framework/skills"
    skill_index = {}

    for skill_file in glob.glob(f"{skills_dir}/*.md"):
        skill_name = os.path.basename(skill_file).replace('.md', '')

        # 读取技能文件
        with open(skill_file, 'r') as f:
            content = f.read()

        # 解析元数据
        metadata = {
            'name': extract_metadata(content, 'name'),
            'type': extract_metadata(content, 'type'),
            'platform': extract_metadata(content, 'platform'),
            'severity': extract_metadata(content, 'severity'),
            'triggers': extract_metadata(content, 'triggers'),
            'file': skill_file
        }

        skill_index[skill_name] = metadata

    # 保存索引
    with open(f"{skills_dir}/skill-index.json", 'w') as f:
        json.dump(skill_index, f, indent=2)

    return skill_index
```

### 技能搜索

```python
def search_skills(query: str) -> list:
    """根据查询搜索相关技能"""

    skill_index = load_skill_index()
    results = []

    query_lower = query.lower()

    for skill_name, metadata in skill_index.items():
        # 搜索触发词
        if metadata.get('triggers'):
            for trigger in metadata['triggers']:
                if trigger.lower() in query_lower:
                    results.append(skill_name)
                    break

        # 搜索平台
        if metadata.get('platform'):
            if metadata['platform'].lower() in query_lower:
                results.append(skill_name)

        # 搜索攻击类型
        if metadata.get('type'):
            if metadata['type'].lower() in query_lower:
                results.append(skill_name)

    return results
```

---

## 📊 技能统计仪表板

```python
def generate_skill_dashboard():
    """生成技能统计仪表板"""

    skills_dir = "/private/tmp/cloud-pentest-framework/skills"

    stats = {
        'total_skills': 0,
        'by_platform': {},
        'by_severity': {},
        'by_type': {},
        'attack_skills': 0,
        'enum_skills': 0,
        'persistence_skills': 0
    }

    for skill_file in glob.glob(f"{skills_dir}/*-attack.md"):
        stats['total_skills'] += 1
        stats['attack_skills'] += 1

        with open(skill_file, 'r') as f:
            content = f.read()

        # 解析元数据
        platform = extract_metadata(content, 'platform')
        severity = extract_metadata(content, 'severity')
        attack_type = extract_metadata(content, 'type')

        stats['by_platform'][platform] = stats['by_platform'].get(platform, 0) + 1
        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        stats['by_type'][attack_type] = stats['by_type'].get(attack_type, 0) + 1

    # 生成仪表板
    dashboard = f"""
# 📊 技能统计仪表板

## 总览
- 总技能数: {stats['total_skills']}
- 攻击技能: {stats['attack_skills']}
- 枚举技能: {stats['enum_skills']}
- 持久化技能: {stats['persistence_skills']}

## 按平台
{format_dict(stats['by_platform'])}

## 按严重程度
{format_dict(stats['by_severity'])}

## 按攻击类型
{format_dict(stats['by_type'])}
"""

    return dashboard
```

---

## 🚀 快速开始指南

### 使用 Agent 执行攻击

```bash
# 1. 启动 Agent
cd /private/tmp/cloud-pentest-framework
python agent.py

# 2. 输入攻击请求
> 我有 AWS 凭证，想测试权限

# 3. Agent 自动:
#    - 识别平台: AWS
#    - 匹配技能: aws-iam-attack
#    - 执行攻击
#    - 生成报告
#    - 建议下一步
```

### 手动执行技能

```bash
# 1. 查找相关技能
python agent.py --search "AWS S3 攻击"

# 2. 查看技能详情
python agent.py --skill aws-s3-attack --show

# 3. 执行技能
python agent.py --execute aws-s3-attack --context '{"access_key": "..."}'
```

---

## 📈 技能开发路线图

### Phase 1: 核心技能（已完成 ✅）

- [x] AWS IAM 攻击
- [x] AWS 元数据攻击
- [x] AWS S3 攻击
- [x] AWS Lambda 攻击
- [x] AWS EC2 攻击
- [x] GCP 攻击
- [x] Azure 攻击
- [x] Jenkins 攻击
- [x] GitLab 攻击
- [x] GitHub 攻击
- [x] Docker 攻击
- [x] Kubernetes 攻击

### Phase 2: 深度技能（已完成 ✅）

- [x] AWS CloudFormation 攻击
- [x] AWS CloudWatch 攻击
- [x] AWS EKS 攻击
- [x] AWS ECS 攻击
- [x] AWS Fargate 攻击
- [x] AWS App Runner 攻击
- [x] GCP Cloud Functions 攻击
- [x] GCP Storage 攻击
- [x] GCP BigQuery 攻击
- [x] GCP Compute Engine 攻击
- [x] Azure Functions 攻击
- [x] Azure DevOps 攻击
- [x] Azure Key Vault 攻击
- [x] CircleCI 攻击
- [x] Bitbucket 攻击
- [x] Concourse 攻击
- [x] Harbor 攻击
- [x] Consul 攻击
- [x] Vault 攻击
- [x] Jira 攻击
- [x] SonarQube 攻击
- [x] Elasticsearch 攻击
- [x] Redis 攻击
- [x] MongoDB 攻击
- [x] Cassandra 攻击
- [x] Kafka 攻击
- [x] RabbitMQ 攻击
- [x] Terraform 攻击

### Phase 3: 高级技能（规划中 📋）

- [ ] 多云攻击链
- [ ] 容器编排平台攻击
- [ ] Service Mesh 攻击
- [ ] Serverless 框架攻击
- [ ] 边缘计算平台攻击

---

## 🔗 技能依赖关系

```mermaid
graph TD
    A[获取凭证] --> B[aws-enum]
    B --> C[aws-iam-attack]
    B --> D[aws-s3-attack]
    C --> E[aws-persistence]
    D --> E

    F[SSRF漏洞] --> G[aws-metadata-attack]
    G --> H[获取临时凭证]
    H --> C

    I[CI/CD访问] --> J[jenkins-attack]
    I --> K[github-actions-attack]
    I --> L[gitlab-attack]

    M[容器访问] --> N[docker-attack]
    M --> O[kubernetes-attack]
    N --> O
    O --> P[aws-metadata-attack]
```

---

## 💡 使用建议

### 1. 从枚举开始

任何渗透测试都应该从**资源枚举**开始：
```
获取凭证 → aws-enum → 发现资源 → 选择攻击技能
```

### 2. 技能组合使用

单个技能可能不够，需要组合使用：
```
凭证 → aws-enum → aws-iam-attack → aws-metadata-attack → aws-s3-attack → aws-persistence
```

### 3. 根据环境选择

- **AWS 环境**: aws-* 系列技能
- **GCP 环境**: gcp-* 系列技能
- **Azure 环境**: azure-* 系列技能
- **CI/CD**: jenkins/gitlab/github-* 系列技能
- **容器**: docker/kubernetes-* 系列技能

---

## 📚 参考资源

- HackTricks Cloud: https://cloud.hacktricks.wiki/
- 技能文件位置: `/private/tmp/cloud-pentest-framework/skills/`
- Agent 管理系统: 本文件

---

**最后更新**: 2025-03-18
**技能总数**: 53+
**维护状态**: 🚀 持续更新中
