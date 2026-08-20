# done-codex-a · 2026-08-19 晚间 · auto_prompt 编排接线

## 分支与提交

- 分支：`feat/2026-08-19-autoprompt-wire`
- 功能提交：`425d0a3b498b55959c01beb15939ac0f53e5034b`
- 署名：`cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`

## 交付内容

- `src/cain_agent/multi_agent/orchestration.py`
  - `build_orchestration()` 注入 `BlackboardAutoPromptMonitor`
  - 支持通过 `recovery_policy` 配置失败策略
  - 默认策略为 `retry -> decompose -> skip`
- `src/cain_agent/multi_agent/manager.py`
  - solver 可恢复失败时由编排层自动重派
  - 重派保留 scope、constraints 与 context
  - 未注入 monitor 时保持原有单次执行行为
- `src/cain_agent/multi_agent/auto_prompt.py`
  - 完善失败记录、策略决策与黑板历史接线
- `tests/test_autoprompt_wire.py`
  - 覆盖默认策略、可配置策略、成功即停止、skip 不重派、上下文保持、
    无 monitor 回退、构造注入、失败历史与解析失败提示词

经典 Route A 回退逻辑保持不变：中心编排异常仍由 report handler 回退到
单会话校验报告。

## 自测结果

- 专项：`pytest -q tests/test_autoprompt_wire.py tests/test_auto_prompt.py tests/test_orchestrate.py`
  - `21 passed in 0.30s`
- 静态检查：相关实现与测试运行 `ruff check`
  - `All checks passed!`
- 全量：`pytest -q`
  - `936 passed, 3 skipped in 2.03s`

## 验收结论

失败自愈已接入中心编排，策略可配置且默认顺序符合派活要求；经典 Route A
可回退，专项与全量测试均通过。
