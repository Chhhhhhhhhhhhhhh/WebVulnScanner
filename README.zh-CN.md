# WebVulnScanner 中文说明

一个轻量级 Python Web 漏洞扫描器,**仅供授权安全测试与教学使用**。
对目标做同源爬取(链接 / 表单 / robots.txt / sitemap.xml / JS 内嵌端点),
可自动登录维持会话,支持多目标批量,运行针对性检测模块,输出带严重
级别、证据、CWE 编号和修复建议的 HTML + JSON (+SARIF) 报告。

> 🔬 仓库自带一个**漏洞靶场** `tests/vulnapp.py`(仅监听 127.0.0.1,
> 数据全部虚构),不用碰任何真实目标即可体验全部检测能力。

**[查看示例报告](docs/sample-report.html)** — 由内置靶场生成。

## 功能模块

| 模块 id | 检测内容 |
|---------|----------|
| `headers` | 缺失的 CSP / HSTS / X-Frame-Options / nosniff 等安全头、未强制 HTTPS、服务器版本泄露、Cookie 缺失 HttpOnly/Secure/SameSite —— 聚合全部爬取页面检查 |
| `fingerprint` | 服务器与运行时指纹、CMS/框架特征、后端语言(依 Cookie)、WAF/CDN 识别 |
| `sensitive` | `.git`/`.svn`/`.env` 泄露、数据库备份、phpinfo、Adminer、Actuator、Swagger、目录列表 —— 带软 404 基线校验、内容验证器、`--wordlist` 自定义字典 |
| `sqli` | 报错型注入(MySQL/MariaDB/PostgreSQL/SQLite/SQL Server/Oracle/DB2/JDBC/PDO 特征)、布尔型盲注差分(易变内容校准,标记"疑似") |
| `xss` | 反射型 XSS:金丝雀反射 + 元字符存活分析,区分 HTML 上下文 / 属性上下文 / 已正确编码 |
| `cmdi` | 命令注入:无害的 `echo 随机标记` 探针(`;` `\|` `&&` 换行 `$()` 反引号 Windows `&`) |
| `lfi` | 路径穿越 / 本地文件包含(以 /etc/passwd、win.ini 内容特征确认) |
| `redirect` | 开放重定向(CWE-601),带中性对照请求,固定跳 SSO 的页面不误报 |
| `cors` | CORS 配置错误(CWE-942):反射任意 Origin(带/不带凭据)、通配符策略 |
| `ssti` | 模板注入(CWE-1336):四种引擎语法的随机算术表达式求值判定 |
| `timing` *(选配 `--time-based`)* | 时间盲注:以响应延迟推断 SQL/命令注入,双重确认;命中的探针会真实休眠,故默认关闭 |
| `domxss` *(选配 `-m domxss`)* | 真浏览器确认的 DOM XSS:金丝雀参数 + sink 补丁。需 `pip install "webvulnscanner[dom]" && playwright install chromium` |

## 安装与使用

```bash
pip install -r requirements.txt        # requests + beautifulsoup4,Python 3.9+

# 基础扫描(全模块,报告输出到 reports/)
python -m scanner -u https://target.example.com

# 批量:目标文件 + 每目标报告 + 汇总报告
python -m scanner --targets urls.txt --fail-on high --format json

# 认证扫描:自动填登录表单并维持会话
python -m scanner -u https://target.example.com \
    --login-url https://target.example.com/login --auth-user demo --auth-pass demo123

# 自定义敏感路径字典
python -m scanner -u https://target.example.com --wordlist paths.txt

# CI 门禁:存在 high 及以上发现则以退出码 1 结束;JSON 输出到 stdout
python -m scanner -u https://target.example.com --fail-on high --format json --no-report

# 回归门禁:对比上次报告,只有"新增"发现才能让门禁失败
python -m scanner -u https://target.example.com --compare reports/scan_prev.json \
    --fail-on high --sarif out.sarif --format json --no-report

# 时间盲注 + 真浏览器 DOM XSS
python -m scanner -u https://target.example.com --time-based
pip install "webvulnscanner[dom]" && playwright install chromium
python -m scanner -u https://target.example.com -m domxss

# 本地靶场(如 DVWA):允许私网地址、跳过证书校验
python -m scanner -u http://127.0.0.1:8080/ --allow-private -k --cookie "PHPSESSID=abc; security=low"
```

完整参数说明见 [English README](README.md)。

## 30 秒安全体验

```bash
# 终端 1:启动内置靶场
python tests/vulnapp.py                # http://127.0.0.1:8099

# 终端 2:扫描它
python -m scanner -u http://127.0.0.1:8099/ --allow-private
```

靶场刻意包含:反射 XSS、报错型 SQLi(GET + 带单次 CSRF 令牌的 POST
表单)、命令注入、路径穿越、开放重定向、模板注入、CORS 配置错误、
暴露的 `.env`、软 404 行为(验证校准能力)、限流端点(验证自适应
退避)、登录后区域(验证认证扫描)、仅 sitemap/JS 可达的端点(验证
爬虫发现能力),以及一个**不应产生任何误报**的安全页面。

## 运行测试

```bash
pip install "webvulnscanner[dev]" && python -m pytest    # 104 个用例全部通过
```

浏览器版 DOM XSS 测试在安装了 playwright 时运行,否则自动跳过。
GitHub Actions 跑 ruff + mypy 与 Python 3.9/3.11/3.13 测试矩阵 +
CLI 冒烟;Release 时经 Trusted Publishing 发布到 PyPI。

## 局限性

* 布尔盲注、时间盲注与属性上下文 XSS 刻意降级为"疑似",请人工复核。
* 爬虫本身不执行 JavaScript(静态挖掘 JS 端点);DOM XSS 由选配的
  浏览器模块覆盖。
* 网络防护按主机做一次 DNS 解析,不防御 DNS rebinding。
* 请对目标保持礼貌:`--delay` 限速、适度线程,只扫描你拥有或被明确授权的目标。

## 免责声明

本工具仅供教学与**授权**安全测试。扫描任何非自有目标前必须获得
明确许可,作者不对滥用行为承担责任。
