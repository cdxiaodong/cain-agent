"""Benchmark 评测运行脚本"""
import argparse
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BenchmarkResult:
    """评测结果"""
    suite: str  # xbow / vuln-tf
    total_scenarios: int
    true_positives: int
    false_positives: int
    false_negatives: int
    avg_duration_sec: float
    avg_token_cost: int
    
    @property
    def recall(self) -> float:
        """检出率"""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def precision(self) -> float:
        """精确率"""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def f1_score(self) -> float:
        """F1 分数"""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)


def run_xbow_benchmark(output_path: Path) -> BenchmarkResult:
    """运行 XBOW 靶场评测（占位实现）
    
    Args:
        output_path: 结果输出路径
    
    Returns:
        BenchmarkResult
    """
    # TODO: 实现 XBOW 靶场评测
    # 1. 部署 XBOW Docker 靶场
    # 2. 遍历场景运行 cain-agent
    # 3. 对比 ground truth 计算指标
    # 4. 生成报告
    
    result = BenchmarkResult(
        suite="xbow",
        total_scenarios=0,
        true_positives=0,
        false_positives=0,
        false_negatives=0,
        avg_duration_sec=0.0,
        avg_token_cost=0
    )
    
    generate_report(result, output_path)
    return result


def run_vuln_tf_benchmark(output_path: Path) -> BenchmarkResult:
    """运行自建靶场评测（占位实现）
    
    Args:
        output_path: 结果输出路径
    
    Returns:
        BenchmarkResult
    """
    # TODO: 实现自建靶场评测
    # 1. terraform apply 部署靶场
    # 2. 运行 cain-agent 云模块
    # 3. 对比预设漏洞计算指标
    # 4. terraform destroy 清理
    
    result = BenchmarkResult(
        suite="vuln-tf",
        total_scenarios=0,
        true_positives=0,
        false_positives=0,
        false_negatives=0,
        avg_duration_sec=0.0,
        avg_token_cost=0
    )
    
    generate_report(result, output_path)
    return result


def generate_report(result: BenchmarkResult, output_path: Path):
    """生成评测报告（markdown）
    
    Args:
        result: 评测结果
        output_path: 输出路径
    """
    report = f"""# Benchmark 评测报告

**评测套件**: {result.suite}
**评测时间**: 2026-08-09

## 核心指标

| 指标 | 值 |
|---|---|
| 总场景数 | {result.total_scenarios} |
| 检出率（Recall） | {result.recall:.1%} |
| 精确率（Precision） | {result.precision:.1%} |
| F1 分数 | {result.f1_score:.3f} |
| 平均耗时 | {result.avg_duration_sec:.1f}s |
| 平均 token 成本 | {result.avg_token_cost} |

## 混淆矩阵

| | 预测阳性 | 预测阴性 |
|---|---|---|
| **实际阳性** | {result.true_positives} | {result.false_negatives} |
| **实际阴性** | {result.false_positives} | - |
"""
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    print(f"报告已生成: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="cain-agent Benchmark 评测")
    parser.add_argument(
        "--suite",
        choices=["xbow", "vuln-tf"],
        required=True,
        help="评测套件：xbow（XBOW 靶场）或 vuln-tf（自建靶场）"
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="结果输出路径（markdown）"
    )
    
    args = parser.parse_args()
    
    if args.suite == "xbow":
        run_xbow_benchmark(args.output)
    elif args.suite == "vuln-tf":
        run_vuln_tf_benchmark(args.output)


if __name__ == "__main__":
    main()
