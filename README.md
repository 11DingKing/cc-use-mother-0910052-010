# 权限审批与交易隔离业务服务

这是一个使用 Python、FastAPI 与 SQLite 实现的纯后端业务服务，包含领域模型、数据访问、业务编排、接口和异常路径测试。项目可在单个 Linux 应用容器内离线运行，使用本地 SQLite 或内存替身，不依赖外部运行服务。

## 安装

```bash
python3 -m pip install -r requirements.txt
```

## 测试

```bash
python3 -m pytest -q
```

## 构建检查

```bash
python3 -m compileall -q app
```

## API 导入冒烟

```bash
python3 -c "from app.main import app; print(len(app.routes))"
```

## 启动

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 审批权限模型（研究/实盘账户隔离）

账户、组合、策略与订单操作统一受带生效区间的审批约束，位于 `app/security/`：

- **资源域与操作**：`account` / `portfolio` / `strategy` / `order` 四类资源；
  `read` 为受限读，`create/update/delete/execute/place_order/cancel_order`
  为敏感操作。
- **申请—批准**：代理人提交带 `valid_from`/`valid_until` 的申请
  （`POST /api/approvals/requests`），批准人通过 `X-Approver-Id` 头独立
  表态；批准人不得是申请人或被授权人本人。
- **生效区间**：授权仅在区间内核验有效；启动与每 5 分钟的过期清理
  （`POST /api/approvals/expire-sweep`）会把到期授权/申请置为过期并作废
  其订单绑定，敏感操作核验时也会惰性清理。
- **撤回与冲突**：原批准人可随时撤回授权（关联未完成订单绑定立即作废）；
  同被授权人/资源/归属且区间重叠、操作相交的批准构成冲突，先返回 `409`，
  须经 `/resolve-conflict` 显式裁决（覆盖批准会把旧授权置为 `superseded`）。
- **提交与恢复双核验**：下单/撤单提交时凭有效授权建立订单一次性绑定；
  会话恢复（`POST /api/trading/orders/{id}/resume`）重新核验绑定与授权
  当前状态，授权撤回/过期后旧会话无法继续操作。
- **重复请求**：`X-Idempotency-Key` 命中时复用首次决定与订单，绝不二次下单；
  失败被拒后同键允许重试。
- **历史留痕与读过滤**：每次执行固化当时的执行人（`executor`）与批准人
  （`approver`）并随订单返回；历史查询按**当前**读权限过滤，失权后既
  不能修改也不能继续读取受限数据，但审计台账永久保留原始执行人/批准人。
- **兼容模式**：未携带身份头的旧调用使用基线主体 `legacy-system`
  （持有可被撤回的全量基线授权）；新接入方应携带 `X-Operator-Id`、
  `X-On-Behalf-Of`（代理归属）、`X-Approval-Token` 与 `X-Idempotency-Key`。

