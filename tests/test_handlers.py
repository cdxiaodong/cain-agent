"""StageHandlers 单元测试 —— fake executor + tmp workspace + 真实 skills/web,零 token 零触网。

覆盖派活单全部自测要求:
- recon 产物落盘结构(endpoints.json + 原始输出文本);
- test handler 生成合法 Finding(过 findings.from_dict 校验,初值 validation_inconclusive);
- SkillLoader 按阶段过滤(真实 skills/web 三技能只进 test 阶段 prompt);
- 脱敏接线(Agent 输出含假 AK 串,落盘内容被 redact);
- 重跑幂等(产物覆盖不追加,findings 按指纹替换不膨胀)。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cain_agent.executor import ExecutorResult, SDKExecutor
from cain_agent.findings import Finding, FindingResult, Severity, fingerprint
from cain_agent.handlers import (
    RECON_ENDPOINTS_FILE,
    RECON_RAW_FILE,
    TEST_RAW_FILE,
    SkillLoader,
    make_recon_handler,
    make_test_handler,
)
from cain_agent.orchestrator import StageContext
from cain_agent.workspace import Workspace

SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"


class FakeExecutor(SDKExecutor):
    """替换 ``run`` 的假 executor:返回预制文本,记录收到的 prompt。"""

    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text
        self.prompts: list[str] = []

    async def run(self, prompt: str) -> ExecutorResult:
        self.prompts.append(prompt)
        return ExecutorResult(text=self._text)


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "scope.yaml").write_text(
        "in_scope:\n  - example.com\nout_of_scope:\n  - admin.example.com\n",
        encoding="utf-8",
    )
    return Workspace(root)


def _ctx(ws: Workspace, stage: str) -> StageContext:
    return StageContext(workspace=ws, stage=stage, artifacts_dir=ws.stage_dir(stage))


def _write_skill(root: Path, name: str, phase: str, body: str) -> None:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    skill_dir.joinpath("SKILL.md").write_text(
        f"---\nname: {name}\ndescription: 测试技能 {name}\nphase: {phase}\n"
        f"severity_focus: medium\n---\n\n{body}\n",
        encoding="utf-8",
    )


# -- SkillLoader:按阶段过滤 + 降级 -------------------------------------------


def test_skill_loader_filters_by_phase(tmp_path: Path) -> None:
    _write_skill(tmp_path, "recon-skill", "recon", "侦察方法论正文")
    _write_skill(tmp_path, "test-skill-a", "test", "测试方法论正文 A")
    _write_skill(tmp_path, "test-skill-b", "test", "测试方法论正文 B")
    _write_skill(tmp_path, "report-skill", "report", "报告方法论正文")
    loader = SkillLoader(tmp_path)

    recon_skills = loader.load("recon")
    test_skills = loader.load("test")
    assert [s.name for s in recon_skills] == ["recon-skill"]
    assert [s.name for s in test_skills] == ["test-skill-a", "test-skill-b"]
    assert all(s.phase == "recon" for s in recon_skills)
    assert "侦察方法论正文" in loader.render("recon")


def test_skill_loader_real_web_skills_are_test_phase() -> None:
    """真实 skills/web 三技能(sqli/ssrf/xss)phase=test,只能被 test 阶段加载。"""
    loader = SkillLoader(SKILLS_ROOT)
    names = {s.name for s in loader.load("test")}
    assert {"sqli", "ssrf", "xss"} <= names
    recon_names = {s.name for s in loader.load("recon")}
    assert not ({"sqli", "ssrf", "xss"} & recon_names)


def test_skill_loader_missing_dir_degrades(tmp_path: Path) -> None:
    loader = SkillLoader(tmp_path / "no-such-skills")
    assert loader.load("recon") == []
    assert loader.issues, "目录缺失必须记录降级原因"
    assert "缺失" in loader.issues[0]
    assert "未加载到技能" in loader.render("test")


def test_skill_loader_zero_hit_phase_recorded(tmp_path: Path) -> None:
    _write_skill(tmp_path, "test-skill", "test", "正文")
    loader = SkillLoader(tmp_path)
    assert loader.load("framework") == []
    assert any("framework" in issue for issue in loader.issues)


# -- recon handler ------------------------------------------------------------

_RECON_OUTPUT = json.dumps(
    {
        "endpoints": [
            {
                "url": "http://example.com/login",
                "method": "POST",
                "params": ["username", "password"],
                "tech": "nginx/1.24",
                "notes": "登录表单",
            },
            "http://example.com/api/users?id=1",
            {"method": "GET"},  # 缺 url,非法条目
        ]
    },
    ensure_ascii=False,
)


def test_recon_handler_artifacts_structure(ws: Workspace) -> None:
    executor = FakeExecutor(_RECON_OUTPUT)
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "recon"))

    assert result.artifacts == [RECON_ENDPOINTS_FILE, RECON_RAW_FILE]
    endpoints = json.loads((ws.root / RECON_ENDPOINTS_FILE).read_text(encoding="utf-8"))
    assert len(endpoints) == 2, "非法条目(缺 url)应被跳过"
    assert endpoints[0]["url"] == "http://example.com/login"
    assert endpoints[0]["params"] == ["username", "password"]
    assert endpoints[1] == {"url": "http://example.com/api/users?id=1"}
    raw = (ws.root / RECON_RAW_FILE).read_text(encoding="utf-8")
    assert "example.com/login" in raw
    assert result.data["endpoint_count"] == 2
    assert result.data["skipped_entries"] == 1


def test_recon_prompt_contains_goal_scope_and_no_expansion(ws: Workspace) -> None:
    executor = FakeExecutor('{"endpoints": []}')
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    handler(_ctx(ws, "recon"))

    prompt = executor.prompts[0]
    assert "存活验证" in prompt and "技术栈指纹" in prompt and "端点提取" in prompt
    assert "禁止资产扩张" in prompt
    # scope 约束复述:原文 + 结构化摘要都在
    assert "example.com" in prompt and "admin.example.com" in prompt
    assert "out_of_scope" in prompt
    # recon 阶段无已加载技能 → 显式降级说明;web 测试技能不得混入
    assert "未加载到技能" in prompt
    assert "SQL 注入测试技能" not in prompt


def test_recon_handler_unparseable_output_writes_empty_endpoints(ws: Workspace) -> None:
    executor = FakeExecutor("模型输出了一堆散文,没有 JSON")
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "recon"))

    endpoints = json.loads((ws.root / RECON_ENDPOINTS_FILE).read_text(encoding="utf-8"))
    assert endpoints == []
    assert "未解析出 JSON" in result.summary
    assert result.data["caveats"], "解析失败必须留痕"


def test_recon_handler_idempotent_overwrite(ws: Workspace) -> None:
    executor = FakeExecutor(_RECON_OUTPUT)
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    handler(_ctx(ws, "recon"))
    first = (ws.root / RECON_ENDPOINTS_FILE).read_text(encoding="utf-8")
    handler(_ctx(ws, "recon"))
    second = (ws.root / RECON_ENDPOINTS_FILE).read_text(encoding="utf-8")
    assert first == second, "重跑覆盖同名产物,内容一致不膨胀"


# -- test handler -------------------------------------------------------------

_TEST_OUTPUT = json.dumps(
    {
        "findings": [
            {
                "cloud": "web",
                "service": "http",
                "resource": "http://example.com/api/users?id=1",
                "issue_type": "sqli",
                "evidence": "id=1 与 id=1' 响应长度稳定差 412 字节",
                "reason": "布尔语义探针有稳定差异",
                "suggested_severity": "critical",
            },
            {"cloud": "web"},  # 缺必填字段,非法条目
        ]
    },
    ensure_ascii=False,
)


def _seed_recon_endpoints(ws: Workspace) -> None:
    (ws.root / "recon" / "endpoints.json").write_text(
        json.dumps([{"url": "http://example.com/api/users?id=1"}], ensure_ascii=False),
        encoding="utf-8",
    )


def test_test_handler_writes_legal_findings(ws: Workspace) -> None:
    _seed_recon_endpoints(ws)
    executor = FakeExecutor(_TEST_OUTPUT)
    handler = make_test_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "test"))

    stored = ws.load_findings()
    assert len(stored) == 1
    finding = Finding.from_dict(stored[0])  # 过数据模型校验即合法
    assert finding.result == FindingResult.VALIDATION_INCONCLUSIVE
    assert finding.issue_type == "sqli"
    # 定级收口:模型建议 critical,规则表无 sqli 命中 → 压到 info
    assert finding.severity == "info"
    assert finding.evidence_hash.startswith("sha256:")
    assert result.data["new_findings"] == 1
    assert result.data["skipped_entries"] == 1
    assert result.artifacts == ["findings.json", TEST_RAW_FILE]


def test_test_prompt_injects_web_skills_and_inputs(ws: Workspace) -> None:
    _seed_recon_endpoints(ws)
    ws.save_assets([{"type": "host", "value": "example.com"}])
    executor = FakeExecutor('{"findings": []}')
    handler = make_test_handler(executor, SkillLoader(SKILLS_ROOT))
    handler(_ctx(ws, "test"))

    prompt = executor.prompts[0]
    # 真实 skills/web 三技能注入 test 阶段
    assert "SQL 注入测试技能" in prompt
    assert "ssrf" in prompt and "xss" in prompt
    # recon 产物 + assets 作为不可信数据进 prompt
    assert "[UNTRUSTED_DATA]" in prompt
    assert "example.com/api/users?id=1" in prompt
    assert '"type": "host"' in prompt
    # L1 边界声明
    assert "L1" in prompt


def test_test_handler_rerun_replaces_same_fingerprint(ws: Workspace) -> None:
    """幂等:重跑产出同指纹 Finding 时原位替换,findings.json 数量不膨胀。"""
    executor = FakeExecutor(_TEST_OUTPUT)
    handler = make_test_handler(executor, SkillLoader(SKILLS_ROOT))
    handler(_ctx(ws, "test"))
    handler(_ctx(ws, "test"))
    stored = [Finding.from_dict(item) for item in ws.load_findings()]
    assert len(stored) == 1
    fps = [fingerprint(f) for f in stored]
    assert len(set(fps)) == 1


def test_test_handler_keeps_other_findings(ws: Workspace) -> None:
    """合并语义:其他来源的 Finding 保留,同指纹替换,不同指纹追加。"""
    other = Finding(
        finding_id="aliyun-oss-public-bucket-001",
        result=FindingResult.CONFIRMED,
        severity=Severity.HIGH,
        evidence_hash="sha256:" + "0" * 64,
        reason="云模块已确认发现",
        cloud="aliyun",
        service="oss",
        resource="acs:oss:::demo-bucket",
        issue_type="public-read",
    )
    ws.save_findings([other.to_dict()])
    executor = FakeExecutor(_TEST_OUTPUT)
    handler = make_test_handler(executor, SkillLoader(SKILLS_ROOT))
    handler(_ctx(ws, "test"))

    stored = [Finding.from_dict(item) for item in ws.load_findings()]
    assert len(stored) == 2
    assert stored[0].finding_id == "aliyun-oss-public-bucket-001"
    assert stored[0].result == FindingResult.CONFIRMED, "其他来源 Finding 不被改写"


# -- 脱敏接线 ------------------------------------------------------------------

_FAKE_AK = "LTAI4GfAKEak12345678TEST"  # 假 AK(≥16 字符),非真实凭证


def test_recon_output_redacted_before_disk(ws: Workspace) -> None:
    output = json.dumps(
        {"endpoints": [{"url": "http://example.com/leak", "notes": f"页面泄露 {_FAKE_AK}"}]},
        ensure_ascii=False,
    )
    executor = FakeExecutor(output)
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    handler(_ctx(ws, "recon"))

    raw = (ws.root / RECON_RAW_FILE).read_text(encoding="utf-8")
    endpoints_text = (ws.root / RECON_ENDPOINTS_FILE).read_text(encoding="utf-8")
    for content in (raw, endpoints_text):
        assert _FAKE_AK not in content, "假 AK 明文不得落盘"
        assert "<REDACTED:aliyun_ak:" in content


def test_test_output_redacted_before_disk(ws: Workspace) -> None:
    output = json.dumps(
        {
            "findings": [
                {
                    "cloud": "web",
                    "service": "http",
                    "resource": "http://example.com/api/users?id=1",
                    "issue_type": "sqli",
                    "evidence": f"响应里回显了 {_FAKE_AK}",
                    "reason": "报错回显疑似凭证样式串",
                }
            ]
        },
        ensure_ascii=False,
    )
    executor = FakeExecutor(output)
    handler = make_test_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "test"))

    raw = (ws.root / TEST_RAW_FILE).read_text(encoding="utf-8")
    findings_text = (ws.root / "findings.json").read_text(encoding="utf-8")
    assert _FAKE_AK not in raw
    assert "<REDACTED:aliyun_ak:" in raw
    assert _FAKE_AK not in findings_text, "证据只哈希落盘,明文(含凭证样式串)不落 findings.json"
    assert result.data["new_findings"] == 1


def test_skill_loader_issues_surfaced_in_caveats(ws: Workspace, tmp_path: Path) -> None:
    """SkillLoader.issues 不再 write-only:技能目录缺失时降级原因进 caveats(issue #9)。"""
    broken_loader = SkillLoader(tmp_path / "no-such-skills")
    executor = FakeExecutor(_RECON_OUTPUT)
    result = make_recon_handler(executor, broken_loader)(_ctx(ws, "recon"))
    caveats = result.data["caveats"]
    assert any("技能目录缺失" in c for c in caveats)
    assert "技能目录缺失" in result.summary, "summary 也应可见"


def test_test_handler_skill_issues_surfaced(ws: Workspace, tmp_path: Path) -> None:
    _seed_recon_endpoints(ws)
    broken_loader = SkillLoader(tmp_path / "no-such-skills")
    executor = FakeExecutor(_TEST_OUTPUT)
    result = make_test_handler(executor, broken_loader)(_ctx(ws, "test"))
    assert any("技能目录缺失" in c for c in result.data["caveats"])
