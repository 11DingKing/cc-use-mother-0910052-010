"""带生效区间审批权限的测试。

覆盖：生效区间核验、代理人申请、撤回、冲突审批、过期清理、重复请求
幂等、订单提交/恢复双时点核验、历史留痕与失权后读过滤。
"""

from datetime import datetime, timedelta

import pytest

from app.security.approval_service import ApprovalService
from app.security.context import PrincipalContext
from app.security.exceptions import (
    ApprovalConflictException,
    ApprovalPendingException,
    PermissionDeniedException,
)
from app.security.ledger import OperationLedger
from app.security.models import Action, OperationContext, ResourceType
from app.services.trading_service import TradingService
from app.trading.simulation_adapter import SimulationAdapter


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
def window(hours_from=-1, hours_to=1):
    now = datetime.utcnow()
    return now + timedelta(hours=hours_from), now + timedelta(hours=hours_to)


def make_grant(
    svc: ApprovalService,
    subject="trader1",
    resource_type=ResourceType.ORDER,
    resource_id="000001",
    actions=None,
    on_behalf_of=None,
    valid_from=None,
    valid_until=None,
    approver="boss",
    requester="agent1",
):
    vf, vu = window()
    valid_from = valid_from or vf
    valid_until = valid_until or vu
    req = svc.submit_request(
        requester=requester,
        subject=subject,
        resource_type=resource_type,
        resource_id=resource_id,
        actions=actions
        or [Action.READ, Action.PLACE_ORDER, Action.CANCEL_ORDER],
        valid_from=valid_from,
        valid_until=valid_until,
        on_behalf_of=on_behalf_of,
    )
    return svc.approve_request(req.request_id, approver), req


@pytest.fixture
def services():
    approvals = ApprovalService()
    ledger = OperationLedger(approvals)
    adapter = SimulationAdapter({"initial_cash": 1000000})
    adapter.connect()
    trading = TradingService(
        adapter, approval_service=approvals, operation_ledger=ledger
    )
    return approvals, ledger, trading


# ---------------------------------------------------------------------------
# 生效区间
# ---------------------------------------------------------------------------
class TestValidityWindow:
    def test_allow_inside_window(self):
        svc = ApprovalService()
        make_grant(svc)
        decision = svc.authorize(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="000001",
            )
        )
        assert decision.outcome.value == "allow"

    def test_deny_before_window(self):
        svc = ApprovalService()
        now = datetime.utcnow()
        make_grant(
            svc,
            valid_from=now + timedelta(hours=1),
            valid_until=now + timedelta(hours=2),
        )
        decision = svc.authorize(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="000001",
            )
        )
        assert decision.outcome.value == "deny"

    def test_deny_after_window_and_sweep_expires(self):
        svc = ApprovalService()
        now = datetime.utcnow()
        grant, _ = make_grant(
            svc,
            valid_from=now - timedelta(hours=2),
            valid_until=now - timedelta(hours=1),
        )
        future = now + timedelta(hours=1)
        sweep = svc.expire_due(future)
        assert sweep["expired_grants"] == 1
        assert svc.repo.get_grant(grant.grant_id).status.value == "expired"

        decision = svc.authorize(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="000001",
                at=future,
            )
        )
        assert decision.outcome.value == "deny"

    def test_wrong_resource_and_action_denied(self):
        svc = ApprovalService()
        make_grant(svc, resource_id="000001", actions=[Action.READ])
        # 不同标的
        d1 = svc.authorize(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="600000",
            )
        )
        assert d1.outcome.value == "deny"
        # 有读权限但无下单权限
        d2 = svc.authorize(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="000001",
            )
        )
        assert d2.outcome.value == "deny"


# ---------------------------------------------------------------------------
# 代理人 / 职责分离 / 待批
# ---------------------------------------------------------------------------
class TestProxyAndDuties:
    def test_pending_request_blocks_sensitive_action(self):
        svc = ApprovalService()
        vf, vu = window()
        svc.submit_request(
            requester="agent1",
            subject="trader1",
            resource_type=ResourceType.ORDER,
            resource_id="000001",
            actions=[Action.PLACE_ORDER],
            valid_from=vf,
            valid_until=vu,
        )
        with pytest.raises(ApprovalPendingException):
            svc.assert_allowed(
                OperationContext(
                    actor="trader1",
                    action=Action.PLACE_ORDER,
                    resource_type=ResourceType.ORDER,
                    resource_id="000001",
                )
            )

    def test_self_approval_forbidden(self):
        svc = ApprovalService()
        vf, vu = window()
        req = svc.submit_request(
            requester="trader1",
            subject="trader1",
            resource_type=ResourceType.ORDER,
            resource_id="000001",
            actions=[Action.PLACE_ORDER],
            valid_from=vf,
            valid_until=vu,
        )
        with pytest.raises(PermissionDeniedException):
            svc.approve_request(req.request_id, "trader1")

    def test_proxy_on_behalf_of_must_match(self):
        svc = ApprovalService()
        make_grant(svc, subject="agent1", on_behalf_of="fund-a")
        # 代理 fund-b 不允许使用 fund-a 的授权
        decision = svc.authorize(
            OperationContext(
                actor="agent1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="000001",
                on_behalf_of="fund-b",
            )
        )
        assert decision.outcome.value == "deny"
        # 代理 fund-a 放行
        decision = svc.authorize(
            OperationContext(
                actor="agent1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="000001",
                on_behalf_of="fund-a",
            )
        )
        assert decision.outcome.value == "allow"


# ---------------------------------------------------------------------------
# 撤回
# ---------------------------------------------------------------------------
class TestWithdrawAndRevoke:
    def test_requester_withdraw_pending(self):
        svc = ApprovalService()
        vf, vu = window()
        req = svc.submit_request(
            requester="agent1",
            subject="trader1",
            resource_type=ResourceType.ORDER,
            resource_id="000001",
            actions=[Action.PLACE_ORDER],
            valid_from=vf,
            valid_until=vu,
        )
        updated = svc.withdraw_request(req.request_id, "agent1")
        assert updated.status.value == "withdrawn"
        with pytest.raises(PermissionDeniedException):
            svc.approve_request(req.request_id, "boss")

    def test_stranger_cannot_withdraw(self):
        svc = ApprovalService()
        vf, vu = window()
        req = svc.submit_request(
            requester="agent1",
            subject="trader1",
            resource_type=ResourceType.ORDER,
            resource_id="000001",
            actions=[Action.PLACE_ORDER],
            valid_from=vf,
            valid_until=vu,
        )
        with pytest.raises(PermissionDeniedException):
            svc.withdraw_request(req.request_id, "outsider")

    def test_revoke_grant_denies_further_action(self, services):
        approvals, _, trading = services
        grant, _ = make_grant(approvals)
        principal = PrincipalContext(actor="trader1")
        result = trading.buy("000001", 100, 10.0, principal=principal)
        assert result["status"] == "filled"

        approvals.revoke_grant(grant.grant_id, "boss", reason="临时授权结束")
        with pytest.raises(PermissionDeniedException):
            trading.buy("000001", 100, 10.0, principal=principal)

    def test_only_original_approver_can_revoke(self, services):
        approvals, _, _ = services
        grant, _ = make_grant(approvals, approver="boss")
        with pytest.raises(PermissionDeniedException):
            approvals.revoke_grant(grant.grant_id, "other-boss")


# ---------------------------------------------------------------------------
# 冲突审批
# ---------------------------------------------------------------------------
class TestConflictApproval:
    def test_overlapping_grant_conflicts_and_can_override(self):
        svc = ApprovalService()
        grant1, req1 = make_grant(svc)

        vf, vu = window(0, 2)  # 与第一条区间重叠
        req2 = svc.submit_request(
            requester="agent2",
            subject="trader1",
            resource_type=ResourceType.ORDER,
            resource_id="000001",
            actions=[Action.PLACE_ORDER],
            valid_from=vf,
            valid_until=vu,
        )
        with pytest.raises(ApprovalConflictException):
            svc.approve_request(req2.request_id, "boss")
        assert svc.get_request(req2.request_id).status.value == "conflict"

        # 显式裁决：覆盖批准，旧授权被置为 superseded
        grant2 = svc.resolve_conflict(
            req2.request_id, "boss", approve_with_override=True
        )
        assert svc.get_grant(grant1.grant_id).status.value == "superseded"
        assert svc.get_grant(grant2.grant_id).status.value == "active"

    def test_conflict_resolve_reject_keeps_original(self):
        svc = ApprovalService()
        grant1, _ = make_grant(svc)
        vf, vu = window(0, 2)
        req2 = svc.submit_request(
            requester="agent2",
            subject="trader1",
            resource_type=ResourceType.ORDER,
            resource_id="000001",
            actions=[Action.PLACE_ORDER],
            valid_from=vf,
            valid_until=vu,
        )
        with pytest.raises(ApprovalConflictException):
            svc.approve_request(req2.request_id, "boss")
        svc.resolve_conflict(
            req2.request_id, "boss", approve_with_override=False, note="维持原授权"
        )
        assert svc.get_request(req2.request_id).status.value == "rejected"
        assert svc.get_grant(grant1.grant_id).status.value == "active"

    def test_non_overlapping_windows_do_not_conflict(self):
        svc = ApprovalService()
        now = datetime.utcnow()
        make_grant(
            svc,
            valid_from=now - timedelta(hours=2),
            valid_until=now - timedelta(hours=1),
        )
        req = svc.submit_request(
            requester="agent2",
            subject="trader1",
            resource_type=ResourceType.ORDER,
            resource_id="000001",
            actions=[Action.PLACE_ORDER],
            valid_from=now + timedelta(hours=1),
            valid_until=now + timedelta(hours=2),
        )
        grant = svc.approve_request(req.request_id, "boss")
        assert grant.status.value == "active"


# ---------------------------------------------------------------------------
# 重复请求幂等
# ---------------------------------------------------------------------------
class TestIdempotency:
    def test_authorize_replays_first_decision(self):
        svc = ApprovalService()
        ctx = OperationContext(
            actor="trader1",
            action=Action.PLACE_ORDER,
            resource_type=ResourceType.ORDER,
            resource_id="000001",
            idempotency_key="key-1",
        )
        d1 = svc.authorize(ctx)
        d2 = svc.authorize(ctx)
        assert d1.outcome is d2.outcome
        assert "复用决定" in d2.reason

    def test_duplicate_buy_places_single_order(self, services):
        approvals, _, trading = services
        make_grant(approvals)
        p1 = PrincipalContext(actor="trader1", idempotency_key="dup-1")
        p2 = PrincipalContext(actor="trader1", idempotency_key="dup-1")
        r1 = trading.buy("000001", 100, 10.0, principal=p1)
        r2 = trading.buy("000001", 100, 10.0, principal=p2)
        assert r1["order_id"] == r2["order_id"]
        orders = trading.adapter.get_orders()
        assert len(orders) == 1

    def test_retry_after_failure_with_same_key_succeeds(self, services):
        # 资金不足导致首次下单被适配器拒绝（绑定作废），同键重试应能成功
        approvals, _, trading = services
        make_grant(approvals)
        principal_key = dict(actor="trader1", idempotency_key="retry-1")
        from app.services.trading_service import TradingException

        with pytest.raises(TradingException):
            trading.buy("000001", 1000000, 10.0, principal=PrincipalContext(**principal_key))
        result = trading.buy("000001", 100, 10.0, principal=PrincipalContext(**principal_key))
        assert result["status"] == "filled"


# ---------------------------------------------------------------------------
# 订单提交与恢复双时点核验
# ---------------------------------------------------------------------------
class TestCommitAndResume:
    def test_resume_allowed_while_grant_live(self, services):
        approvals, _, trading = services
        make_grant(approvals)
        principal = PrincipalContext(actor="trader1")
        order = trading.buy("000001", 100, 10.0, principal=principal)
        resume = trading.resume_order(order["order_id"], principal=principal)
        assert resume["outcome"] == "allow"

    def test_resume_denied_after_revoke(self, services):
        approvals, _, trading = services
        grant, _ = make_grant(approvals)
        principal = PrincipalContext(actor="trader1")
        order = trading.buy("000001", 100, 10.0, principal=principal)
        approvals.revoke_grant(grant.grant_id, "boss", reason="临时授权结束")
        with pytest.raises(PermissionDeniedException):
            trading.resume_order(order["order_id"], principal=principal)

    def test_resume_denied_after_expiry(self, services):
        approvals, _, trading = services
        now = datetime.utcnow()
        make_grant(
            approvals,
            valid_from=now - timedelta(hours=2),
            valid_until=now + timedelta(minutes=1),
        )
        principal = PrincipalContext(actor="trader1")
        order = trading.buy("000001", 100, 10.0, principal=principal)

        # 授权结束，旧会话尝试恢复下单 → 拒绝
        future = now + timedelta(hours=1)
        decision = trading.approvals.resume_order(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id=order["order_id"],
                at=future,
            ),
            order["order_id"],
        )
        assert decision.outcome.value == "deny"
        assert "失效" in decision.reason

    def test_resume_without_binding_denied(self, services):
        approvals, _, trading = services
        make_grant(approvals)
        decision = trading.approvals.resume_order(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="ORD_NEVER",
            ),
            "ORD_NEVER",
        )
        assert decision.outcome.value == "deny"

    def test_resume_proxy_mismatch_denied(self, services):
        approvals, _, trading = services
        make_grant(approvals, subject="agent1", on_behalf_of="fund-a")
        principal = PrincipalContext(actor="agent1", on_behalf_of="fund-a")
        order = trading.buy("000001", 100, 10.0, principal=principal)
        decision = trading.approvals.resume_order(
            OperationContext(
                actor="agent1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id=order["order_id"],
                on_behalf_of="fund-b",
            ),
            order["order_id"],
        )
        assert decision.outcome.value == "deny"

    def test_cancel_order_requires_grant(self, services):
        approvals, _, trading = services
        make_grant(approvals, actions=[Action.READ, Action.PLACE_ORDER])
        principal = PrincipalContext(actor="trader1")
        order = trading.buy("000001", 100, 10.0, order_type="market", principal=principal)
        # 仅有下单权限无撤单权限（市价单成交后撤单也会被业务状态拦截，
        # 这里直接验证撤单核验：换一个未成交限价单场景由权限先拒绝）
        with pytest.raises(PermissionDeniedException):
            trading.cancel_order(order["order_id"], principal=principal)


# ---------------------------------------------------------------------------
# 历史留痕与失权读过滤
# ---------------------------------------------------------------------------
class TestLedgerAndReadFilter:
    def test_order_history_preserves_executor_and_approver(self, services):
        approvals, ledger, trading = services
        make_grant(approvals)
        principal = PrincipalContext(actor="trader1")
        order = trading.buy("000001", 100, 10.0, principal=principal)
        assert order["executor"] == "trader1"
        assert order["approver"] == "boss"

        records = ledger.list_for(ResourceType.ORDER, order["order_id"])
        assert records[-1].executor == "trader1"
        assert records[-1].approver == "boss"

    def test_revoked_subject_cannot_read_restricted_history(self, services):
        approvals, _, trading = services
        grant, _ = make_grant(approvals)
        principal = PrincipalContext(actor="trader1")
        order = trading.buy("000001", 100, 10.0, principal=principal)

        # 失权前可读
        assert len(trading.get_orders(principal=principal)) == 1
        approvals.revoke_grant(grant.grant_id, "boss")
        # 失权后：列表不可见、详情 403，但留痕本身保留
        assert trading.get_orders(principal=principal) == []
        with pytest.raises(PermissionDeniedException):
            trading.get_order(order["order_id"], principal=principal)

    def test_unauthorized_user_cannot_place_or_toggle_strategy(self, services):
        approvals, _, trading = services
        principal = PrincipalContext(actor="newbie")
        with pytest.raises(PermissionDeniedException):
            trading.buy("000001", 100, 10.0, principal=principal)
        # 卖出在触碰持仓数据前也应先被权限拦截，不泄露持仓有无
        with pytest.raises(PermissionDeniedException):
            trading.sell("000001", 100, 10.0, principal=principal)
        with pytest.raises(PermissionDeniedException):
            trading.enable_auto_trade(True, principal=principal)

    def test_strategy_execute_grant_allows_toggle(self, services):
        approvals, _, trading = services
        make_grant(
            approvals,
            resource_type=ResourceType.STRATEGY,
            resource_id="auto-trade",
            actions=[Action.EXECUTE],
        )
        trading.enable_auto_trade(
            True, principal=PrincipalContext(actor="trader1")
        )
        assert trading._auto_trade_enabled is True

    def test_wildcard_read_plus_specific_execute_grant(self):
        # 同目标同操作的重叠授权在审批阶段就必须冲突裁决，因此运行时
        # 至多有一条授权覆盖某操作；这里验证读/写可分授不同粒度。
        svc = ApprovalService()
        now = datetime.utcnow()
        # 通配授权仅有读权限
        make_grant(
            svc,
            resource_id="*",
            actions=[Action.READ],
            valid_from=now - timedelta(hours=3),
            valid_until=now + timedelta(hours=3),
        )
        # 具体标的授权有下单权限（操作不与通配授权相交，避免区间冲突）
        make_grant(
            svc,
            resource_id="000001",
            actions=[Action.PLACE_ORDER],
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=1),
        )
        decision = svc.authorize(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="000001",
            )
        )
        assert decision.outcome.value == "allow"


# ---------------------------------------------------------------------------
# 审计台账：每个决定都可追溯
# ---------------------------------------------------------------------------
class TestAuditTrail:
    def test_all_decisions_recorded(self):
        svc = ApprovalService()
        make_grant(svc)
        svc.authorize(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="000001",
            )
        )
        svc.authorize(
            OperationContext(
                actor="trader1",
                action=Action.PLACE_ORDER,
                resource_type=ResourceType.ORDER,
                resource_id="600000",
            )
        )
        decisions = svc.list_decisions(actor="trader1")
        outcomes = {d.outcome.value for d in decisions}
        assert "allow" in outcomes and "deny" in outcomes

    def test_audit_events_cover_lifecycle(self):
        svc = ApprovalService()
        grant, req = make_grant(svc)
        svc.revoke_grant(grant.grant_id, "boss", reason="x")
        types = {e.event_type for e in svc.audit_events()}
        assert {"request_submitted", "request_approved", "grant_revoked"} <= types
