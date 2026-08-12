"""业务逻辑绕过攻击技术库 (30 条) — 流程/状态/经济/竞态深度变体."""
from __future__ import annotations

LOGIC_BYPASS_TECHNIQUES: list[dict] = [
    # ---------- 流程类 ----------
    {"id": "logic_flow_skip", "name": "流程跳步",
     "description": "跳过中间步骤直接执行最终操作",
     "payloads": [
         "跳过验证码/确认步骤直接提交",
         "直接调用最终API而不走前置流程",
     ]},
    {"id": "logic_state_confusion", "name": "状态混淆",
     "description": "利用状态机设计缺陷混淆状态",
     "payloads": [
         "先触发错误状态再进入正常流程",
         "重复请求同一操作观察状态变化",
     ]},
    {"id": "logic_race", "name": "条件竞争",
     "description": "并发请求绕过一次性/校验逻辑",
     "payloads": [
         "并发提交多个相同flag/请求, 观察是否重复计分",
         "并发提交两个相同修补包",
     ]},
    {"id": "logic_constraint", "name": "约束绕过",
     "description": "绕过输入约束/配额/频率限制",
     "payloads": [
         "超长/超短输入边界测试",
         "频率限制绕过: 换IP/加参数",
     ]},
    {"id": "logic_chain_state", "name": "链路状态污染",
     "description": "污染中间状态影响后续流程",
     "payloads": [
         "先创建一个异常状态的资源, 再走正常流程",
         "篡改 session 中步骤完成标志",
     ]},
    {"id": "logic_step_replay", "name": "步骤重放",
     "description": "重放中间步骤覆盖最终状态",
     "payloads": [
         "完成后重放'完成'步骤看是否重复计分",
         "重放中间步骤覆盖最终确认状态",
     ]},
    {"id": "logic_skip_verify", "name": "跳过校验步骤",
     "description": "直接调用校验后的处理接口",
     "payloads": [
         "先触发校验, 再用旧会话直接执行后续操作",
         "把校验接口的响应缓存后直接调用业务接口",
     ]},
    # ---------- 数值/经济类 ----------
    {"id": "logic_negative_value", "name": "负值/溢出利用",
     "description": "负数、极大数、浮点精度绕过金额/数量校验",
     "payloads": [
         "数量传 -1 或 0 观察业务行为",
         "传 2147483647 / 1e308 溢出测试",
     ]},
    {"id": "logic_decimal_trick", "name": "小数精度",
     "description": "利用浮点精度/四舍五入差异",
     "payloads": [
         "金额传 0.1/0.001 观察累计误差",
         "数量传 1.9 四舍五入到 2",
     ]},
    {"id": "logic_quantity_zero", "name": "零值滥用",
     "description": "零数量/零金额交易",
     "payloads": [
         "购买数量 0 但结算成功",
         "金额 0 的订单直接完成",
     ]},
    {"id": "logic_coupon_stack", "name": "优惠叠加",
     "description": "叠加多个折扣/优惠超过限制",
     "payloads": [
         "重复使用同一优惠码",
         "叠加多个互斥优惠",
     ]},
    {"id": "logic_currency_swap", "name": "货币切换",
     "description": "利用多币种汇率差套利",
     "payloads": [
         "下单用美元, 结算用人民币观察汇率处理",
     ]},
    # ---------- 权限/身份类 ----------
    {"id": "logic_privilege_guess", "name": "权限猜测",
     "description": "猜测高权限接口/操作路径",
     "payloads": [
         "尝试 /api/admin/delete /api/super/ 等路径",
         "用已知用户 token 调用管理操作",
     ]},
    {"id": "logic_type_confusion", "name": "类型混淆",
     "description": "数组/布尔/字符串类型变换绕过校验",
     "payloads": [
         "把布尔字段传字符串 'true' 或数组 [true]",
         "JSON 中 id 传数组 ['1','2'] 越权遍历",
     ]},
    {"id": "logic_time_tamper", "name": "时间篡改",
     "description": "修改时间戳/过期时间绕过时效校验",
     "payloads": [
         "把过期时间戳改为未来值",
         "发送过期 token/会话观察是否仍有效",
     ]},
    {"id": "logic_idempotency", "name": "幂等性滥用",
     "description": "利用幂等设计重复获利",
     "payloads": [
         "重复提交相同请求 ID 观察是否重复处理",
     ]},
    {"id": "logic_identity_switch", "name": "身份切换",
     "description": "切换身份视角获取额外权限",
     "payloads": [
         "以游客身份完成操作后切换登录用户",
         "注销后重放旧请求观察身份检查",
     ]},
    # ---------- 校验绕过类 ----------
    {"id": "logic_verify_race", "name": "校验竞态",
     "description": "校验与执行之间插入并发请求",
     "payloads": [
         "校验通过后立即并发执行多次",
         "修改校验通过后的资源再执行",
     ]},
    {"id": "logic_captcha_bypass", "name": "验证码绕过",
     "description": "验证码复用/删除参数绕过",
     "payloads": [
         "删除验证码参数直接提交",
         "复用同一验证码多次",
     ]},
    {"id": "logic_client_side", "name": "客户端校验绕过",
     "description": "只做前端校验的参数直接改包",
     "payloads": [
         "前端限制输入长度, 直接改包传超长值",
         "前端只读字段在请求中修改",
     ]},
    {"id": "logic_default_value", "name": "默认值利用",
     "description": "依赖默认值/未定义字段",
     "payloads": [
         "不传权限字段观察默认角色",
         "传 null/空对象观察默认行为",
     ]},
    {"id": "logic_null_abuse", "name": "空值滥用",
     "description": "null/空数组绕过非空校验",
     "payloads": [
         "对象传 null 而非 {}",
         "数组传空 [] 跳过遍历校验",
     ]},
    # ---------- 状态机/会话类 ----------
    {"id": "logic_session_reuse", "name": "会话复用",
     "description": "复用旧会话/并发会话",
     "payloads": [
         "同一账号多会话并行操作",
         "登出后复用旧 session 继续操作",
     ]},
    {"id": "logic_token_reuse", "name": "令牌复用",
     "description": "一次性令牌重复使用",
     "payloads": [
         "同一 CSRF token 重放多次",
         "重置密码链接重复使用",
     ]},
    {"id": "logic_step_order", "name": "步骤顺序颠倒",
     "description": "颠倒步骤顺序绕过前置条件",
     "payloads": [
         "先执行最后一步再补前置步骤",
         "乱序调用流程接口",
     ]},
    {"id": "logic_pagination", "name": "分页遍历",
     "description": "遍历分页获取全部数据",
     "payloads": [
         "page 传负数/0 观察返回全部数据",
         "page_size 超限返回全量",
     ]},
    {"id": "logic_filter_inject", "name": "过滤注入",
     "description": "注入排序/过滤字段",
     "payloads": [
         "order=password,balance 排序泄露字段",
         "filter 参数注入敏感字段",
     ]},
    {"id": "logic_export_abuse", "name": "导出滥用",
     "description": "导出功能泄露全量数据",
     "payloads": [
         "导出接口不带分页/过滤条件",
         "导出格式切换 (csv->json) 泄露字段",
     ]},
    {"id": "logic_import_abuse", "name": "导入滥用",
     "description": "批量导入覆盖数据",
     "payloads": [
         "导入重复数据覆盖已有记录",
         "导入含特殊字符的数据污染下游",
     ]},
    {"id": "logic_notification_abuse", "name": "通知滥用",
     "description": "利用通知/消息通道探测信息",
     "payloads": [
         "找回密码通知观察账号是否存在",
         "通知内容注入链接",
     ]},
    {"id": "logic_logout_flow", "name": "登出流程缺陷",
     "description": "登出不失效 token/会话",
     "payloads": [
         "登出后旧 token 是否仍有效",
         "登出接口并发调用观察状态",
     ]},
]
