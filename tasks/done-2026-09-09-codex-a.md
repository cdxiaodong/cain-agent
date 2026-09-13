# done-2026-09-09-codex-a(任务2:feat/2026-09-09-bac-evidence-input)

> 执行:监工(Lead 09-13 委托,任务1 验收通过后续领);交付见分支 tip 提交。

## 基线

main=4766ff3(任务1 已合入),1124 passed / 3 skipped。

## 交付

`src/cain_agent/web/bac_evidence.py`(新):
- `load_evidence(data: Mapping) -> tuple[RequestPair, ResponseDiff]` 纯函数
- 只验证/构造,不调 `judge_bac`——输入合法仅代表证据包可解析
- 三层键白名单 + 敏感键名片段黑名单(headers/cookies/token/body/
  authorization/secret/password/credential)双闸:未知与敏感字段均拒
- bool↔int/str↔float 类型冒充显式拒绝;状态码 100-599;similarity
  [0,1] 有限数;VictimSideChange 枚举校验
- `_reject -> NoReturn`:错误消息只含字段路径与原因,不含输入值
- 零 IO / 零 HTTP / 零 CLI / 零新依赖

`tests/test_bac_evidence.py`(新):29 例——合法构造(含可选字段)/缺必填
×10(parametrize)/顶层缺节/bool 冒充 int/int 冒充 bool/str 冒充 float/
状态码越界×4/similarity 越界与非有限×4/非法枚举/敏感键×6(parametrize,
含假 token canary)/未知普通字段/顶层未知键/canary 不回流报错/合法输入
不含「已确认」语义。

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1153 passed, 3 skipped in 2.55s
```

## 阻塞

无。任务3(report-trust)留池,可继续领取。
