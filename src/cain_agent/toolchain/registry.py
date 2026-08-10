"""ToolRegistry —— 工具注册表（发现、注册、路由）

参考 T3MP3ST 工具链设计（36+ 工具），按 MITRE ATT&CK 杀链阶段分类。
严格限制为**只读工具**，禁止任何写入/利用/修改操作。

内置工具清单（只读白名单）：
┌──────────────┬──────────────────────────────────────────────────────┐
│ 侦察 RECON   │ subfinder, amass, assetfinder, waybackurls, gau,     │
│ (TA0043)     │ httpx, httprobe, dnsx, shuffledns, massdns,          │
│              │ dig, whois, whatweb, wafw00f, cloud_enum              │
├──────────────┼──────────────────────────────────────────────────────┤
│ 扫描 SCAN    │ nuclei, nmap, rustscan, naabu, testssl.sh,           │
│ (TA0007)     │ sslscan, nikto, wapiti, zap-baseline, ffuf           │
├──────────────┼──────────────────────────────────────────────────────┤
│ 验证 EXPLOIT │ curl, httpie, wget, sqlmap(check-only),              │
│ (TA0001)     │ xsstrike(crawl-only), commix(check-only),            │
│              │ tplmap(detect-only)                                   │
├──────────────┼──────────────────────────────────────────────────────┤
│ 后渗透 POST  │ aws-cli(read-only), gcloud(list), az-cli(read),      │
│ (TA0008)     │ kubectl(get), docker(inspect), trivy(scan),          │
│              │ grype(scan), syft(catalog)                            │
├──────────────┼──────────────────────────────────────────────────────┤
│ 报告 REPORT  │ jq, yq, dasel, md-processor                          │
│ (TA0011)     │                                                      │
└──────────────┴──────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cain_agent.toolchain.tool import Tool, ToolCategory, ToolSpec

if TYPE_CHECKING:
    from cain_agent.toolchain.readonly_guard import ReadonlyGuard

# ── 工具规范清单（36+ 只读工具）───────────────────────────────────────────

_BUILTIN_TOOL_SPECS: list[ToolSpec] = [
    # ============ 侦察 RECON (TA0043) ============
    # 子域名枚举
    ToolSpec(
        name="subfinder",
        category=ToolCategory.RECON,
        description="被动子域名枚举（API 聚合）",
        binary="subfinder",
        example="subfinder -d example.com -silent",
    ),
    ToolSpec(
        name="amass",
        category=ToolCategory.RECON,
        description="深度子域名枚举（OWASP 项目）",
        binary="amass",
        dangerous_flags=["-db", "--database"],
        example="amass enum -passive -d example.com",
    ),
    ToolSpec(
        name="assetfinder",
        category=ToolCategory.RECON,
        description="轻量级资产发现",
        binary="assetfinder",
        example="assetfinder example.com",
    ),
    ToolSpec(
        name="shuffledns",
        category=ToolCategory.RECON,
        description="基于解析的子域名爆破（只读：仅解析，不写结果文件）",
        binary="shuffledns",
        dangerous_flags=["-o", "-output", "-w", "-wd"],
        example="shuffledns -d example.com -r resolvers.txt -silent",
    ),
    ToolSpec(
        name="massdns",
        category=ToolCategory.RECON,
        description="高性能 DNS 解析器（仅读取结果到 stdout）",
        binary="massdns",
        dangerous_flags=["-o", "-w"],
        example="massdns -r resolvers.txt domains.txt",
    ),

    # URL 发现
    ToolSpec(
        name="waybackurls",
        category=ToolCategory.RECON,
        description="从 Wayback Machine 获取历史 URL",
        binary="waybackurls",
        example="waybackurls example.com",
    ),
    ToolSpec(
        name="gau",
        category=ToolCategory.RECON,
        description="从 AlienVault/CommonCrawl/Wayback 获取 URL",
        binary="gau",
        example="gau example.com",
    ),
    ToolSpec(
        name="katana",
        category=ToolCategory.RECON,
        description="Web 爬虫（只读爬取）",
        binary="katana",
        dangerous_flags=["-store-field", "-field", "-output", "-o"],
        example="katana -u https://example.com -silent",
    ),

    # 存活探测
    ToolSpec(
        name="httpx",
        category=ToolCategory.RECON,
        description="HTTP 存活探测 + 指纹识别",
        binary="httpx",
        example="httpx -l domains.txt -status-code -title -tech-detect",
    ),
    ToolSpec(
        name="httprobe",
        category=ToolCategory.RECON,
        description="HTTP/HTTPS 存活探测（轻量）",
        binary="httprobe",
        example="cat domains.txt | httprobe",
    ),
    ToolSpec(
        name="dnsx",
        category=ToolCategory.RECON,
        description="DNS 工具包（A/AAAA/CNAME/MX/NS 查询）",
        binary="dnsx",
        example="dnsx -d example.com -a -cname -mx -ns -silent",
    ),

    # 指纹/技术识别
    ToolSpec(
        name="whatweb",
        category=ToolCategory.RECON,
        description="Web 技术指纹识别",
        binary="whatweb",
        example="whatweb https://example.com",
    ),
    ToolSpec(
        name="wafw00f",
        category=ToolCategory.RECON,
        description="WAF 检测与识别",
        binary="wafw00f",
        example="wafw00f https://example.com",
    ),
    ToolSpec(
        name="cloud_enum",
        category=ToolCategory.RECON,
        description="云资源枚举（AWS/GCP/Azure 公开资源发现）",
        binary="cloud_enum",
        example="cloud_enum -k example",
    ),

    # 基础网络工具
    ToolSpec(
        name="dig",
        category=ToolCategory.RECON,
        description="DNS 查询",
        binary="dig",
        example="dig example.com ANY",
    ),
    ToolSpec(
        name="whois",
        category=ToolCategory.RECON,
        description="WHOIS 注册信息查询",
        binary="whois",
        example="whois example.com",
    ),
    ToolSpec(
        name="nslookup",
        category=ToolCategory.RECON,
        description="DNS 查询（跨平台）",
        binary="nslookup",
        example="nslookup example.com",
    ),

    # ============ 扫描 SCAN (TA0007) ============
    # 端口扫描
    ToolSpec(
        name="nmap",
        category=ToolCategory.SCAN,
        description="端口扫描与服务版本检测（只读 SYN/Connect 扫描）",
        binary="nmap",
        dangerous_flags=["--script", "-sC", "-oN", "-oX", "-oG", "-oA"],
        example="nmap -sV -sC -p- example.com",
    ),
    ToolSpec(
        name="rustscan",
        category=ToolCategory.SCAN,
        description="高速端口扫描",
        binary="rustscan",
        example="rustscan -a example.com -- -sV",
    ),
    ToolSpec(
        name="naabu",
        category=ToolCategory.SCAN,
        description="快速端口扫描（Go 实现）",
        binary="naabu",
        dangerous_flags=["-output", "-o", "-json"],
        example="naabu -host example.com -silent",
    ),

    # 漏洞扫描（只读模板）
    ToolSpec(
        name="nuclei",
        category=ToolCategory.SCAN,
        description="模板化漏洞扫描（仅使用检测模板，不触发利用）",
        binary="nuclei",
        dangerous_flags=["-delete", "-rm", "-exploit", "-code"],
        example="nuclei -u https://example.com -severity critical,high,medium -silent",
    ),
    ToolSpec(
        name="nikto",
        category=ToolCategory.SCAN,
        description="Web 服务器安全扫描",
        binary="nikto",
        dangerous_flags=["-Format", "-output", "-o", "-Save", "-mutate"],
        example="nikto -h https://example.com -Tuning 1234567890",
    ),

    # SSL/TLS 检测
    ToolSpec(
        name="testssl",
        category=ToolCategory.SCAN,
        description="SSL/TLS 配置安全检测",
        binary="testssl.sh",
        example="testssl.sh https://example.com",
    ),
    ToolSpec(
        name="sslscan",
        category=ToolCategory.SCAN,
        description="SSL/TLS 密码套件检测",
        binary="sslscan",
        example="sslscan example.com",
    ),

    # Web 扫描
    ToolSpec(
        name="wapiti",
        category=ToolCategory.SCAN,
        description="Web 漏洞扫描（只读模块：仅检测，不注入）",
        binary="wapiti",
        dangerous_flags=["--flush-session", "--store-session"],
        example="wapiti -u https://example.com --scope domain",
    ),
    ToolSpec(
        name="zap-baseline",
        category=ToolCategory.SCAN,
        description="OWASP ZAP 基线扫描（只读，自动模式）",
        binary="zap-baseline.py",
        example="zap-baseline.py -t https://example.com",
    ),

    # Fuzzing（只读探测）
    ToolSpec(
        name="ffuf",
        category=ToolCategory.SCAN,
        description="Web Fuzzer（仅目录/参数发现，不发送 payload）",
        binary="ffuf",
        dangerous_flags=["-o", "-of", "-od", "-output-dir"],
        example="ffuf -u https://example.com/FUZZ -w wordlist.txt",
    ),

    # ============ 验证 EXPLOIT (TA0001 - 只读验证) ============
    ToolSpec(
        name="curl",
        category=ToolCategory.EXPLOIT,
        description="HTTP 请求（仅 GET/HEAD/OPTIONS）",
        binary="curl",
        dangerous_flags=["-X DELETE", "-X PUT", "-X POST", "-X PATCH",
                        "-d", "--data", "-F", "--form", "-T", "--upload-file"],
        example="curl -sI https://example.com",
    ),
    ToolSpec(
        name="httpie",
        category=ToolCategory.EXPLOIT,
        description="HTTP 客户端（GET/HEAD 只读请求）",
        binary="http",
        dangerous_flags=["POST", "PUT", "DELETE", "PATCH"],
        example="http GET https://example.com",
    ),
    ToolSpec(
        name="wget",
        category=ToolCategory.EXPLOIT,
        description="文件下载（只读获取）",
        binary="wget",
        dangerous_flags=["--post-data", "--post-file", "--method=POST", "--method=PUT"],
        example="wget -qO- https://example.com",
    ),
    ToolSpec(
        name="sqlmap",
        category=ToolCategory.EXPLOIT,
        description="SQL 注入检测（仅检测模式，不利用）",
        binary="sqlmap",
        dangerous_flags=["--os-shell", "--os-cmd", "--file-read", "--file-write",
                        "--dump", "--dump-all", "--columns", "--tables"],
        example="sqlmap -u 'https://example.com?id=1' --batch --level=1 --risk=1",
    ),
    ToolSpec(
        name="xsstrike",
        category=ToolCategory.EXPLOIT,
        description="XSS 检测（仅爬虫/检测模式）",
        binary="xsstrike",
        dangerous_flags=["--data", "--params", "--headers"],
        example="xsstrike -u 'https://example.com?q=test' --crawl",
    ),
    ToolSpec(
        name="commix",
        category=ToolCategory.EXPLOIT,
        description="命令注入检测（仅检测，不执行）",
        binary="commix",
        dangerous_flags=["--os-cmd", "--file-read", "--file-write", "--file-upload"],
        example="commix --url='https://example.com?cmd=test' --batch",
    ),
    ToolSpec(
        name="tplmap",
        category=ToolCategory.EXPLOIT,
        description="模板注入检测（仅检测模式）",
        binary="tplmap",
        dangerous_flags=["--os-cmd", "--os-shell", "--bind-shell"],
        example="tplmap -u 'https://example.com?name=test'",
    ),
    ToolSpec(
        name="openssl",
        category=ToolCategory.EXPLOIT,
        description="TLS/证书检测（s_client 只读连接）",
        binary="openssl",
        example="openssl s_client -connect example.com:443 -servername example.com",
    ),

    # ============ 后渗透 POST (TA0008 - 只读信息收集) ============
    # 云平台（只读操作）
    ToolSpec(
        name="aws",
        category=ToolCategory.POST,
        description="AWS CLI（仅 list/describe/get 系列只读命令）",
        binary="aws",
        dangerous_flags=["create-", "delete-", "put-", "update-", "modify-",
                        "add-", "remove-", "attach-", "detach-", "rm", "mv", "cp"],
        example="aws s3 ls --no-sign-request",
    ),
    ToolSpec(
        name="gcloud",
        category=ToolCategory.POST,
        description="GCloud CLI（仅 list/describe 只读命令）",
        binary="gcloud",
        dangerous_flags=["create", "delete", "update", "set", "add", "remove",
                        "patch", "apply", "replace"],
        example="gcloud compute instances list",
    ),
    ToolSpec(
        name="az",
        category=ToolCategory.POST,
        description="Azure CLI（仅 show/list 只读命令）",
        binary="az",
        dangerous_flags=["create", "delete", "update", "set", "add", "remove"],
        example="az vm list --output table",
    ),

    # 容器/K8s（只读）
    ToolSpec(
        name="kubectl",
        category=ToolCategory.POST,
        description="Kubernetes（仅 get/describe/logs 只读命令）",
        binary="kubectl",
        dangerous_flags=["apply", "create", "delete", "edit", "patch", "replace",
                        "scale", "exec", "attach", "cp", "port-forward", "run",
                        "set", "annotate", "label", "taint"],
        example="kubectl get pods --all-namespaces",
    ),
    ToolSpec(
        name="docker",
        category=ToolCategory.POST,
        description="Docker（仅 inspect/logs/ps/images 只读命令）",
        binary="docker",
        dangerous_flags=["run", "exec", "build", "push", "pull", "rm", "rmi",
                        "stop", "start", "restart", "kill", "create", "commit",
                        "tag", "save", "load", "export", "import"],
        example="docker ps -a",
    ),

    # 容器镜像扫描
    ToolSpec(
        name="trivy",
        category=ToolCategory.POST,
        description="容器镜像漏洞扫描",
        binary="trivy",
        dangerous_flags=["--fix", "--exit-code"],
        example="trivy image nginx:latest --severity HIGH,CRITICAL",
    ),
    ToolSpec(
        name="grype",
        category=ToolCategory.POST,
        description="SBOM 漏洞扫描",
        binary="grype",
        example="grype nginx:latest",
    ),
    ToolSpec(
        name="syft",
        category=ToolCategory.POST,
        description="SBOM 生成（软件物料清单）",
        binary="syft",
        example="syft nginx:latest -o json",
    ),

    # ============ 报告 REPORT (TA0011) ============
    ToolSpec(
        name="jq",
        category=ToolCategory.REPORT,
        description="JSON 处理与格式化",
        binary="jq",
        example="jq '.' findings.json",
    ),
    ToolSpec(
        name="yq",
        category=ToolCategory.REPORT,
        description="YAML 处理与格式化",
        binary="yq",
        example="yq '.' scope.yaml",
    ),
    ToolSpec(
        name="dasel",
        category=ToolCategory.REPORT,
        description="多格式数据处理（JSON/YAML/TOML/CSV）",
        binary="dasel",
        example="dasel -f findings.json",
    ),
]


class ToolRegistry:
    """工具注册表：管理所有可用工具（只读白名单）。

    内置 46 个只读安全工具，覆盖侦察/扫描/验证/后渗透/报告 5 类。
    """

    def __init__(self, guard: ReadonlyGuard | None = None) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self.guard = guard
        self._register_builtin_tools()
        # sync tool names into ReadonlyGuard whitelist
        if self.guard is not None:
            self.guard.ALLOWED_READONLY_TOOLS = set(self._tools.keys())

    def register(self, tool: Tool) -> None:
        """注册工具（规范归档）。"""
        spec = tool.spec()
        if not spec.readonly:
            raise ValueError(f"工具 {spec.name} 不是只读工具，拒绝注册")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        """获取工具规范。"""
        return self._tools.get(name)

    def list_by_category(self, category: ToolCategory) -> list[ToolSpec]:
        """按分类列出工具。"""
        return [t for t in self._tools.values() if t.category == category]

    def list_all(self) -> list[ToolSpec]:
        """列出所有已注册工具。"""
        return list(self._tools.values())

    def is_allowed(self, tool_name: str, args: list[str]) -> bool:
        """检查工具+参数是否允许（只读约束）。"""
        spec = self.get(tool_name)
        if not spec:
            return False

        # 检查危险参数
        for arg in args:
            for dangerous in spec.dangerous_flags:
                if dangerous in arg:
                    return False

        # 守门员二次校验
        if self.guard and not self.guard.check(tool_name, args):
            return False

        return True

    def _register_builtin_tools(self) -> None:
        """注册内置只读工具清单。"""
        for spec in _BUILTIN_TOOL_SPECS:
            self._tools[spec.name] = spec
