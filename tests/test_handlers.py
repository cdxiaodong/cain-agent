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

from cain_agent.executor import ExecutorResult, SDKExecutor, ToolCallRecord, complete_tool_call
from cain_agent.findings import Finding, FindingResult, Severity, fingerprint
from cain_agent.handlers import (
    RECON_ENDPOINTS_FILE,
    RECON_RAW_FILE,
    RECON_STATUS_FILE,
    TEST_RAW_FILE,
    SkillLoader,
    _provenance_for,
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


def test_https_provenance_separates_port_from_status(ws: Workspace) -> None:
    call = ToolCallRecord(
        tool_use_id="request-1",
        name="Bash",
        input={"command": "curl -i https://example.com/"},
    )
    complete_tool_call(
        call,
        'HTTP/2 403\nalt-svc: h3=":443"; ma=86400\n\nforbidden',
        succeeded=True,
    )
    provenance = _provenance_for(
        {"resource": "https://example.com/", "evidence": "forbidden"},
        ExecutorResult(tool_calls=[call]),
        _ctx(ws, "test"),
    )

    assert provenance is not None
    assert provenance["status_code"] == 403
    assert provenance["port"] == 443


def test_missing_http_status_makes_provenance_incomplete(ws: Workspace) -> None:
    call = ToolCallRecord(
        tool_use_id="request-1",
        name="Bash",
        input={"command": "curl -i https://example.com/"},
    )
    complete_tool_call(call, 'alt-svc: h3=":443"; ma=86400', succeeded=True)

    provenance = _provenance_for(
        {"resource": "https://example.com/", "evidence": "unknown"},
        ExecutorResult(tool_calls=[call]),
        _ctx(ws, "test"),
    )

    assert call.status_code is None
    assert provenance is None


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
    """Every repository web skill is visible in test and absent from recon."""
    loader = SkillLoader(SKILLS_ROOT)
    names = {s.name for s in loader.load("test")}
    expected = {path.parent.name for path in SKILLS_ROOT.glob("web/*/SKILL.md")}
    assert names == expected
    recon_names = {s.name for s in loader.load("recon")}
    assert not (expected & recon_names)
    assert not any("技能已排除" in issue for issue in loader.issues)


def test_skill_loader_missing_frontmatter_is_explicit(tmp_path: Path) -> None:
    path = tmp_path / "missing" / "SKILL.md"
    path.parent.mkdir()
    path.write_text("# Missing metadata\n", encoding="utf-8")
    loader = SkillLoader(tmp_path)

    assert loader.load("test") == []
    assert any("missing/SKILL.md" in issue and "frontmatter" in issue for issue in loader.issues)


def test_skill_loader_malformed_frontmatter_is_explicit(tmp_path: Path) -> None:
    path = tmp_path / "broken" / "SKILL.md"
    path.parent.mkdir()
    path.write_text("---\nname: [broken\n---\n# Broken\n", encoding="utf-8")
    loader = SkillLoader(tmp_path)

    assert loader.load("test") == []
    assert any("broken/SKILL.md" in issue and "格式错误" in issue for issue in loader.issues)


def test_skill_loader_duplicate_name_excludes_later_path(tmp_path: Path) -> None:
    _write_skill(tmp_path, "a", "test", "first")
    _write_skill(tmp_path, "b", "test", "second")
    second = tmp_path / "b" / "SKILL.md"
    second.write_text(second.read_text(encoding="utf-8").replace("name: b", "name: a"), encoding="utf-8")
    loader = SkillLoader(tmp_path)

    skills = loader.load("test")
    assert [(skill.name, skill.path) for skill in skills] == [("a", "a/SKILL.md")]
    assert any("name='a'" in issue and "冲突" in issue for issue in loader.issues)


def test_skill_loader_missing_required_metadata_is_explicit(tmp_path: Path) -> None:
    path = tmp_path / "incomplete" / "SKILL.md"
    path.parent.mkdir()
    path.write_text("---\nname: incomplete\nphase: test\n---\n# Incomplete\n", encoding="utf-8")
    loader = SkillLoader(tmp_path)

    assert loader.load("test") == []
    assert any("description" in issue and "severity_focus" in issue for issue in loader.issues)


def test_skill_loader_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    """A copy-paste error that repeats a frontmatter key must not silently
    resolve to whichever value PyYAML happens to keep last."""
    path = tmp_path / "dupe-key" / "SKILL.md"
    path.parent.mkdir()
    path.write_text(
        "---\nname: dupe-key\ndescription: d\nphase: test\nphase: recon\n"
        "severity_focus: medium\n---\n# Dupe key\n",
        encoding="utf-8",
    )
    loader = SkillLoader(tmp_path)

    assert loader.load("test") == []
    assert loader.load("recon") == []
    assert any("dupe-key/SKILL.md" in issue and "格式错误" in issue for issue in loader.issues)


def test_skill_loader_same_name_different_phases_is_not_a_conflict(tmp_path: Path) -> None:
    """Reusing a name across two *different* phases is not a real conflict —
    each phase renders its own independent skill set. Regression: the loader
    used to register every scanned file's name globally before filtering by
    phase, so a same-named skill in an unrelated phase could silently exclude
    the one actually being loaded for the requested phase."""
    _write_skill(tmp_path, "shared-name", "recon", "recon body")
    recon_skill_path = tmp_path / "shared-name" / "SKILL.md"
    test_dir = tmp_path / "zzz-shared-name"
    test_dir.mkdir()
    (test_dir / "SKILL.md").write_text(
        recon_skill_path.read_text(encoding="utf-8").replace("phase: recon", "phase: test"),
        encoding="utf-8",
    )

    loader = SkillLoader(tmp_path)
    recon_skills = loader.load("recon")
    test_skills = loader.load("test")

    assert [s.name for s in recon_skills] == ["shared-name"]
    assert [s.name for s in test_skills] == ["shared-name"]
    assert not any("冲突" in issue for issue in loader.issues)


def test_skill_loader_invalid_severity_focus_is_explicit(tmp_path: Path) -> None:
    path = tmp_path / "bad-severity" / "SKILL.md"
    path.parent.mkdir()
    path.write_text(
        "---\nname: bad-severity\ndescription: d\nphase: test\n"
        "severity_focus: catastrophic\n---\n# Bad severity\n",
        encoding="utf-8",
    )
    loader = SkillLoader(tmp_path)

    assert loader.load("test") == []
    assert any("severity_focus" in issue for issue in loader.issues)


def test_skill_loader_non_string_description_is_explicit(tmp_path: Path) -> None:
    path = tmp_path / "bad-description" / "SKILL.md"
    path.parent.mkdir()
    path.write_text(
        "---\nname: bad-description\ndescription: [1, 2]\nphase: test\n"
        "severity_focus: medium\n---\n# Bad description\n",
        encoding="utf-8",
    )
    loader = SkillLoader(tmp_path)

    assert loader.load("test") == []
    assert any("description" in issue for issue in loader.issues)


def test_recon_handler_surfaces_skill_loader_issues_as_caveats(ws: Workspace) -> None:
    skills_root = ws.root / "broken-skills"
    (skills_root / "broken").mkdir(parents=True)
    (skills_root / "broken" / "SKILL.md").write_text("# No frontmatter\n", encoding="utf-8")

    executor = FakeExecutor('{"endpoints": []}')
    handler = make_recon_handler(executor, SkillLoader(skills_root))
    result = handler(_ctx(ws, "recon"))

    assert any("技能加载问题" in caveat for caveat in result.data["caveats"])
    assert "技能加载问题" in result.summary


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

    assert result.artifacts == [RECON_ENDPOINTS_FILE, RECON_RAW_FILE, RECON_STATUS_FILE]
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


# -- recon output parsing robustness (regression: prose / fences / multiple ---
# -- JSON blobs must not collapse a valid final object into recon_invalid) ----

_RECON_SCHEMA_JSON = json.dumps(
    {"endpoints": [{"url": "http://example.com/login", "method": "GET"}]},
    ensure_ascii=False,
)


def _assert_recon_status_valid_single_endpoint(ws: Workspace, result: object) -> None:
    status = json.loads((ws.root / RECON_STATUS_FILE).read_text(encoding="utf-8"))
    assert status["status"] == "valid"
    assert status["structural_errors"] == []
    assert status["endpoint_count"] == 1
    assert result.data["status"] == "valid"  # type: ignore[attr-defined]
    endpoints = json.loads((ws.root / RECON_ENDPOINTS_FILE).read_text(encoding="utf-8"))
    assert endpoints == [{"url": "http://example.com/login", "method": "GET"}]


def test_recon_handler_parses_clean_json(ws: Workspace) -> None:
    executor = FakeExecutor(_RECON_SCHEMA_JSON)
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "recon"))
    _assert_recon_status_valid_single_endpoint(ws, result)


def test_recon_handler_parses_fenced_json(ws: Workspace) -> None:
    output = f"```json\n{_RECON_SCHEMA_JSON}\n```"
    executor = FakeExecutor(output)
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "recon"))
    _assert_recon_status_valid_single_endpoint(ws, result)


def test_recon_handler_parses_json_after_prose(ws: Workspace) -> None:
    output = (
        "我先侦察了一下目标,发现了一个可测端点,分析过程省略。\n"
        "以下是结构化结果:\n\n"
        f"{_RECON_SCHEMA_JSON}\n\n"
        "以上就是本轮侦察结果。"
    )
    executor = FakeExecutor(output)
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "recon"))
    _assert_recon_status_valid_single_endpoint(ws, result)


def test_recon_handler_recovers_after_malformed_first_attempt(ws: Workspace) -> None:
    """First attempt has a trailing comma (invalid JSON); the model then emits
    a corrected, schema-valid object. The corrected one must win."""
    malformed = '{"endpoints": [{"url": "http://example.com/login",}]}'
    output = f"{malformed}\n上面的 JSON 有语法错误,修正一下:\n\n{_RECON_SCHEMA_JSON}"
    executor = FakeExecutor(output)
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "recon"))
    _assert_recon_status_valid_single_endpoint(ws, result)


def test_recon_handler_selects_final_schema_valid_object_among_several(ws: Workspace) -> None:
    """Multiple *valid* JSON objects appear; only the final one matches the
    recon schema ({"endpoints": [...]})  — an earlier, off-schema-but-valid
    blob must never be silently accepted as the canonical artifact."""
    stray = json.dumps({"note": "只是草稿备注,不是端点schema"}, ensure_ascii=False)
    output = f"草稿备注:\n{stray}\n\n最终结果:\n{_RECON_SCHEMA_JSON}"
    executor = FakeExecutor(output)
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "recon"))
    _assert_recon_status_valid_single_endpoint(ws, result)


def test_recon_handler_selects_final_of_multiple_schema_valid_objects(ws: Workspace) -> None:
    """Two objects both match the recon schema; the *final* one is canonical."""
    first_attempt = json.dumps(
        {"endpoints": [{"url": "http://example.com/old-draft"}]}, ensure_ascii=False
    )
    output = f"第一次尝试:\n{first_attempt}\n\n修正后:\n{_RECON_SCHEMA_JSON}"
    executor = FakeExecutor(output)
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "recon"))
    _assert_recon_status_valid_single_endpoint(ws, result)


def test_recon_handler_completely_invalid_output_is_recon_invalid(ws: Workspace) -> None:
    executor = FakeExecutor("完全没有结构化输出,只有一段自然语言描述,没有任何 JSON。")
    handler = make_recon_handler(executor, SkillLoader(SKILLS_ROOT))
    result = handler(_ctx(ws, "recon"))

    status = json.loads((ws.root / RECON_STATUS_FILE).read_text(encoding="utf-8"))
    assert status["status"] == "recon_invalid"
    assert status["structural_errors"] == ["json_parse_failed"]
    assert status["endpoint_count"] == 0
    assert result.data["status"] == "recon_invalid"
    endpoints = json.loads((ws.root / RECON_ENDPOINTS_FILE).read_text(encoding="utf-8"))
    assert endpoints == []


def test_recon_to_test_pipeline_survives_prose_and_multiple_json_blobs(ws: Workspace) -> None:
    """End-to-end regression for the reported bug: recon agent returns prose
    plus more than one JSON object; the final object is valid and contains
    endpoints. This must not produce recon_invalid/endpoint_count 0, and the
    test stage must actually run against the recovered endpoints."""
    draft = json.dumps({"endpoints": [{"url": "http://example.com/draft"}]}, ensure_ascii=False)
    recon_output = (
        "让我先分析一下目标站点的结构……\n"
        f"初步草稿:\n{draft}\n\n"
        "重新核对后,最终结果如下:\n\n"
        f"{_RECON_SCHEMA_JSON}\n"
    )
    recon_handler = make_recon_handler(FakeExecutor(recon_output), SkillLoader(SKILLS_ROOT))
    recon_result = recon_handler(_ctx(ws, "recon"))
    assert recon_result.data["status"] == "valid"
    assert recon_result.data["endpoint_count"] == 1

    test_executor = FakeExecutor('{"findings": []}')
    test_result = make_test_handler(test_executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert test_result.data.get("status") != "recon_invalid"
    assert len(test_executor.prompts) == 1, "test stage must actually run once recon is valid"


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
