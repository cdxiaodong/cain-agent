# done-2026-10-06(用户指令:Webpack_extract 添加到信息收集阶段)

> 指令来源:用户 10-06 直接指令(优先于派活单流程)。

## 交付

- `skills/web/webpack-js-analysis/SKILL.md`(phase: recon):Chrome 扩展
  Webpack_extract 的方法论命令行等价实现(Bash/Grep 可跑,headless 可用)
- 五步流程 + 三层模型 + 证据/禁止节;接口进 endpoints(source 标注),
  密钥形态只记类型+哈希,明文不落盘

## 过程失误与修复(如实披露)

1. 首次提交用 `pytest | tail` 管道,退出码被吞,**带 2 个测试失败合入**
   (skill_format 三节缺失 + recon prompt 旧断言)——违反三门纪律;
2. 8 分钟后定位并修复:补三节 + 更新断言,1312 passed 全绿;
3. 教训已吸收:后续所有验证命令不再接管道,或用 `set -o pipefail`。

## 三门(修复后)

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1312 passed, 3 skipped in 3.53s
```
