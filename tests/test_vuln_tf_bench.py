"""vuln-tf 三场景离线静态跑分测试 — 检出/误报/漏报/耗时口径全钉死。"""

from __future__ import annotations

from pathlib import Path

from bench.run_benchmark import run_vuln_tf_benchmark
from bench.vuln_tf_static import (
    ALL_PRIVESC_RULES,
    SCENARIOS,
    TF_DIR,
    VulnTfScenario,
    detect_oss_public_buckets,
    detect_ram_privesc,
    run_all,
    run_scenario,
)


def test_tf_dir_exists_with_all_scenario_files() -> None:
    for sc in SCENARIOS:
        for f in sc.tf_files:
            assert (TF_DIR / f).exists(), f"missing tf file: {f}"


def test_oss_public_bucket_detected_private_clean() -> None:
    text = (TF_DIR / "main.tf").read_text(encoding="utf-8")
    hits = detect_oss_public_buckets(text)
    entities = [d.entity for d in hits]
    assert "vuln_public_read" in entities
    assert all(d.hit == "oss:public-read" for d in hits)
    assert "safe_private_bucket" not in entities  # private 桶零命中


def test_ram_overprivileged_two_rules() -> None:
    text = (TF_DIR / "main.tf").read_text(encoding="utf-8")
    hits = {d.hit for d in detect_ram_privesc(text)}
    assert "ram:AttachPolicyToSelf" in hits
    assert "ram:CreateAccessKey-for-HighPriv" in hits


def test_ram_admin_hits_all_five_readonly_clean() -> None:
    text = (TF_DIR / "scene3-main.tf").read_text(encoding="utf-8")
    hits = detect_ram_privesc(text)
    rule_hits = {d.hit for d in hits}
    for rule in ALL_PRIVESC_RULES:
        assert rule in rule_hits
    entities = {d.entity for d in hits}
    assert "safe_readonly_user" not in entities  # 只读用户零命中


def test_all_scenarios_pass_no_fp_no_missing() -> None:
    for r in run_all():
        assert not r.false_positives, f"{r.scenario}: unexpected FP {r.false_positives}"
        assert not r.expected_missing, f"{r.scenario}: missing {r.expected_missing}"
        assert r.detections, f"{r.scenario}: no detections"
        assert r.elapsed_s >= 0
        assert r.token_cost == 0  # 纯静态,零 token


def test_benchmark_entrypoint_full_metrics(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    result = run_vuln_tf_benchmark(out)
    assert result.total_scenarios == 3
    assert result.true_positives == 8  # 1 OSS + 2 过度授权 + 5 管理员
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.avg_token_cost == 0
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "vuln-tf" in text
    assert "100.0%" in text  # recall
    assert "1.000" in text   # F1 满分


def test_run_scenario_isolated_expectation_failure_counted() -> None:
    """漏报路径:伪造一个预期命中但 tf 不含的场景,验证 expected_missing 计数。"""
    sc = VulnTfScenario(name="fake", tf_files=("variables.tf",), expect_hits=("oss:public-read",))
    r = run_scenario(sc)
    assert r.expected_missing == ["oss:public-read"]
    assert not r.detected_ok
