# 端口对照表 · 使用说明

> **版本**：1.0 ｜ **更新**：2026-11-01T07:00:00+08:00
> **数据源**：微软官方 KB832017 + 综合整理
> **用途**：端口管家网页小工具的数据源（知识层，不参与关闭判定——见 README §8）

---

## 一、文件清单

| 文件 | 用途 | 给谁看 |
|------|------|--------|
| `ports.json` | **主数据文件**，程序/AI 读取 | 程序、AI |
| `ports.md` | 人读说明 + 使用指南 | 人 |

---

## 二、JSON 结构说明

### 顶层字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `version` | string | 数据版本号 |
| `updated` | string | 更新日期 |
| `source` | string | 数据来源 |
| `categories` | array of object | 分类列表（8 类），元素为 `{ "name": 分类名, "count": 该分类条数 }`——注意是**对象数组不是字符串数组** |
| `ports` | array | **端口记录数组**（核心数据） |
| `dynamicRanges` | array | 动态端口范围 |

### 每条端口记录字段

| 字段 | 类型 | 说明 | 示例 |
|------|------|------|------|
| `port` | number | 端口号 | `80` |
| `protocol` | string | 协议 | `"TCP"` / `"UDP"` / `"TCP/UDP"` |
| `category` | string | 分类（见下表） | `"数据库-国产"` |
| `service` | string | 服务标识（英文，程序用） | `"MySQL"` |
| `name` | string | 中文名 | `"MySQL数据库"` |
| `description` | string | 说明 | `"MySQL数据库默认端口"` |
| `vendor` | string | 厂商 | `"武汉达梦"` |
| `os` | array | 适用系统 | `["Windows", "Linux"]` |
| `tags` | array | 标签（便于搜索） | `["database", "mysql"]` |
| `generic` | bool | `true`=通用知识条目（AI 不得当本机进程身份）；`false`=本机实扫条目 | `true` |
| `scope` | string | `"general"`=通用整理；`"local"`=2026-11-01 本机实扫补录（§七） | `"local"` |

### 八大分类

| 分类 | 说明 | 记录数 |
|------|------|--------|
| Windows系统服务 | Windows自带的系统服务端口 | 12 |
| 网络基础协议 | HTTP/FTP/DNS/SMTP等基础协议 | 23 |
| 数据库-国际 | MySQL/Oracle/PostgreSQL等 | 8 |
| 数据库-国产 | 达梦/人大金仓/GaussDB/OceanBase等 | 10 |
| 中间件-国产 | 金蝶Apusic/东方通TongWeb/中创InforSuite | 16 |
| 国内常用软件 | 微信/钉钉/企业微信/飞书/ERP等 | 21 |
| Web中间件 | Apache/Tomcat/WebLogic等 | 5 |
| 开发常用端口 | 开发服务器/管理面板/ES等 | 13 |

> **共 108 条端口记录**（同一端口可能对应多个服务，如 5432 同时是 PostgreSQL 和 GaussDB；
> 5000 端口原"UPnP"条目经核源不成立已删除，常见 UPnP 为 1900/2869——1.0.1 修正）

---

## 三、程序使用示例

### 示例1：按端口号查询

```javascript
// 网页小工具中加载 JSON
const data = await fetch('ports.json').then(r => r.json());

// 查询端口 5236
const result = data.ports.filter(p => p.port === 5236);
// 返回: 达梦数据库
```

### 示例2：按分类查询

```javascript
// 查询所有国产数据库端口
const result = data.ports.filter(p => p.category === '数据库-国产');
```

### 示例3：按关键词搜索

```javascript
// 搜索"信创"相关端口
const result = data.ports.filter(p => 
  p.tags.includes('信创') || p.vendor.includes('信创')
);
```

### 示例4：按协议查询

```javascript
// 查询所有 UDP 端口
const result = data.ports.filter(p => p.protocol === 'UDP');
```

### 示例5：AI 读取

```
直接读取 ports.json 的 ports 数组，
按用户提问的端口号或软件名，返回匹配的记录。
```

---

## 四、端口速查表（人读）

### Windows 系统服务

| 端口 | 协议 | 服务 | 说明 |
|------|------|------|------|
| 135 | TCP | RPC | 远程过程调用 |
| 137 | UDP | NetBIOS-NS | 名称解析 |
| 138 | UDP | NetBIOS-DGM | 数据报 |
| 139 | TCP | NetBIOS-SSN | 会话服务 |
| 445 | TCP | SMB/CIFS | 文件共享 |
| 3389 | TCP | RDP | 远程桌面 |
| 5985 | TCP | WinRM-HTTP | 远程管理 |
| 5986 | TCP | WinRM-HTTPS | 远程管理(加密) |
| 1900 | UDP | SSDP | 设备发现 |
| 515 | TCP | LPD | 打印服务 |
| 23 | TCP | Telnet | 远程终端 |

### 网络基础协议

| 端口 | 协议 | 服务 | 说明 |
|------|------|------|------|
| 20 | TCP | FTP-Data | FTP数据传输 |
| 21 | TCP | FTP-Control | FTP控制 |
| 22 | TCP | SSH/SFTP | 安全远程登录 |
| 25 | TCP | SMTP | 邮件发送 |
| 53 | TCP/UDP | DNS | 域名解析 |
| 67/68 | UDP | DHCP | 动态IP分配 |
| 69 | UDP | TFTP | 简单文件传输 |
| 80 | TCP | HTTP | 网页明文 |
| 110 | TCP | POP3 | 邮件接收 |
| 123 | UDP | NTP | 时间同步 |
| 143 | TCP | IMAP | 邮件访问 |
| 161/162 | UDP | SNMP | 网络管理 |
| 443 | TCP | HTTPS | 网页加密 |
| 465 | TCP | SMTPS | SMTP加密 |
| 514 | UDP | Syslog | 系统日志 |
| 587 | TCP | SMTP-Submission | 邮件提交 |
| 636 | TCP | LDAPS | LDAP加密 |
| 993 | TCP | IMAPS | IMAP加密 |
| 995 | TCP | POP3S | POP3加密 |

### 数据库

| 端口 | 数据库 | 厂商 | 类别 |
|------|--------|------|------|
| 1433 | SQL Server | Microsoft | 国际 |
| 1521 | Oracle | Oracle | 国际 |
| 3306 | MySQL | MySQL | 国际 |
| 33060 | MySQL-X | MySQL | 国际 |
| 5432 | PostgreSQL | PostgreSQL | 国际 |
| 6379 | Redis | Redis | 国际 |
| 27017 | MongoDB | MongoDB | 国际 |
| 11211 | Memcached | Memcached | 国际 |
| **5236** | **达梦 DM** | **武汉达梦** | **国产** |
| **54321** | **人大金仓** | **北京人大金仓** | **国产** |
| **5432** | **GaussDB/openGauss** | **华为** | **国产** |
| **2881** | **OceanBase直连** | **蚂蚁** | **国产** |
| **2883** | **OceanBase OBProxy** | **蚂蚁** | **国产** |
| **4000** | **TiDB** | **PingCAP** | **国产** |
| **3306** | **PolarDB** | **阿里云** | **国产** |
| **5432** | **Vastbase** | **海量数据** | **国产** |
| **5866** | **HighGo瀚高** | **瀚高** | **国产** |
| **3306** | **GoldenDB** | **中兴** | **国产** |

### 国产中间件

**金蝶天燕 Apusic**

| 端口 | 模块 |
|------|------|
| 6848 | 管控端口 |
| 6888 | HTTP |
| 6887 | HTTPS |
| 6837 | IIOP |
| 6876 | JMS |
| 6886 | JMX |
| 6866 | OSGI Shell |
| 8000 | Java Debugger |

**东方通 TongWeb**

| 端口 | 模块 |
|------|------|
| 9060 | 管理控制台 |

**中创 InforSuite**

| 端口 | 模块 |
|------|------|
| 8060 | Admin |
| 8080 | HTTP Instance |
| 7676 | JMS |
| 3700 | IIOP |
| 8181 | HTTP_SSL |
| 8686 | JMX_Admin |
| 6666 | OSGI Shell |
| 9009 | Java Debugger |

### 国内常用软件

| 软件 | 端口 | 说明 |
|------|------|------|
| 微信 | 80 / 443 / 8080 | 服务端监听 |
| 钉钉 | 443 / 5222 | 5222为长连接 |
| 企业微信 | 443 / 8443 | — |
| 飞书 | 443 | — |
| 微信公众号回调 | 8080 | 本地调试，需转发80/443 |
| 阿里云控制台 | 443 | — |
| 腾讯云控制台 | 443 | — |
| 金蝶/用友ERP | 1433 / 3306 | 后端数据库 |

### 动态端口范围

| 范围 | 系统 | 说明 |
|------|------|------|
| 49152-65535 | Windows Vista+/Server 2008+ | 客户端动态端口 |
| 1025-5000 | Windows XP/Server 2003 | 客户端动态端口 |

> 动态端口范围**不固定对应某个程序**，是客户端临时连接时动态分配的。

---

## 五、注意事项

1. **端口可被修改**：以上均为**默认值**，实际部署中可能被修改
2. **同一端口多服务**：如 5432 同时对应 PostgreSQL 和 GaussDB，查询时返回所有匹配
3. **国产数据库**：端口可在配置文件中修改
4. **国产中间件**：端口被占用会导致**无法启动**，部署前检查
5. **零依赖**：JSON 纯文本，网页工具直接 fetch，无需任何库

---

## 六、查端口被谁占了（Windows）

```powershell
# 查占用某端口的进程
netstat -ano | findstr :端口号
tasklist /FI "PID eq 你的PID"

# 图形界面
Win+R → resmon → 网络 → 监听端口
```

---

## 七、本机补充端口（2026-11-01 扫描）

> 扫描本机监听端口后补充，涵盖本机实际运行的软件。
> 本节端口在 `ports.json` 中 `scope: "local"`、`generic: false`——本机实扫可作归属参考；
> 但进程身份仍以 `rules.json`/`port_map.json` 为权威（对照表只是知识层）。

| 端口 | 进程 | 说明 |
|------|------|------|
| 11434 | ollama | Ollama本地AI模型服务 |
| 4709 | wpscloudsvr | WPS云服务同步 |
| 8011 | Weixin | 微信PC客户端本地监听 |
| 9010 | lghub_agent | lghub代理服务 |
| 9128 | quark | 夸克浏览器 |
| 9180 | lghub_updater | lghub更新服务 |
| 3092 / 8899 | node | Node.js开发服务 |
| 4280 | opencode | OpenCode开发工具 |
| 42050 | OneDrive | OneDrive同步服务 |
| 49853 / 53234 | Doubao | 豆包AI本地服务 |

> **动态端口**（运行时分配，不固定）：49664-49671（系统服务）、57134-57140（Loomy）、60xxx（WorkBuddy/sandbox）等，不加入固定对照表。

---

*数据整理：Loomy · 2026-11-01（含本机扫描补充）*
