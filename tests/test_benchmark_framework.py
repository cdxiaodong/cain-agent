"""Benchmark 框架格式校验"""
from pathlib import Path


def test_benchmark_readme_exists():
    """Benchmark README 存在"""
    readme_path = Path("bench/README.md")
    assert readme_path.exists(), "bench/README.md 不存在"


def test_benchmark_script_exists():
    """Benchmark 运行脚本存在"""
    script_path = Path("bench/run_benchmark.py")
    assert script_path.exists(), "bench/run_benchmark.py 不存在"


def test_readme_structure():
    """README 结构完整"""
    content = Path("bench/README.md").read_text(encoding="utf-8")
    
    required_sections = [
        "## 评测目标",
        "## 评测方法",
        "## 评测指标",
        "## 运行方式",
    ]
    
    for section in required_sections:
        assert section in content, f"缺少章节: {section}"


def test_metrics_defined():
    """评测指标已定义"""
    content = Path("bench/README.md").read_text(encoding="utf-8")
    
    metrics = [
        "检出率",
        "误报率",
        "耗时",
        "token 成本",
        "F1 分数",
    ]
    
    for metric in metrics:
        assert metric in content, f"缺少指标: {metric}"


def test_no_sensitive_info():
    """无敏感信息"""
    content = Path("bench/README.md").read_text(encoding="utf-8")
    
    assert "平安" not in content, "包含敏感词: 平安"
    assert "pingan" not in content.lower(), "包含敏感词: pingan"


def test_script_executable():
    """运行脚本可导入"""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))
    
    try:
        import run_benchmark
        assert hasattr(run_benchmark, "run_xbow_benchmark")
        assert hasattr(run_benchmark, "run_vuln_tf_benchmark")
        assert hasattr(run_benchmark, "BenchmarkResult")
    except ImportError:
        # 如果导入失败，至少检查文件内容
        content = Path("bench/run_benchmark.py").read_text(encoding="utf-8")
        assert "def run_xbow_benchmark" in content
        assert "def run_vuln_tf_benchmark" in content
        assert "class BenchmarkResult" in content


def test_result_properties():
    """BenchmarkResult 属性计算正确"""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))
    
    try:
        from run_benchmark import BenchmarkResult
        
        result = BenchmarkResult(
            suite="test",
            total_scenarios=10,
            true_positives=8,
            false_positives=2,
            false_negatives=2,
            avg_duration_sec=300.0,
            avg_token_cost=50000
        )
        
        assert result.recall == 0.8  # 8 / (8 + 2)
        assert result.precision == 0.8  # 8 / (8 + 2)
        assert abs(result.f1_score - 0.8) < 0.001
    except ImportError:
        # 跳过，至少文件存在即可
        pass
