"""审批权限核心服务。

负责申请、批准、拒绝、撤回、冲突裁决、过期清理与每次操作的实时核验。
所有决定（含拒绝与冲突）都写入审计台账；敏感操作在提交（commit）与
恢复（resume）两个时点分别重新核验，授权失效后旧会话无法继续下单。
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.security.exceptions import (
    ApprovalConflictException,
    ApprovalPendingException,
    PermissionDeniedException,
)
from app.security.models import (
    Action,
    ApprovalGrant,
    ApprovalRequest,
    DecisionOutcome,
    GrantStatus,
    OperationContext,
    OrderBinding,
    PermissionDecision,
    RequestStatus,
    ResourceType,
    SENSITIVE_ACTIONS,
    new_token,
    utcnow,
)
from app.security.repository import ApprovalRepository

logger = logging.getLogger(__name__)


class ApprovalService:
    """带生效区间的审批权限服务。"""

    def __init__(self, repository: Optional[ApprovalRepository] = None):
        self.repo = repository or ApprovalRepository()

    # ------------------------------------------------------------------
    # 申请
    # ------------------------------------------------------------------
    def submit_request(
        self,
        *,
        requester: str,
        subject: str,
        resource_type: ResourceType,
        actions: List[Action],
        valid_from: datetime,
        valid_until: datetime,
        resource_id: str = "*",
        on_behalf_of: Optional[str] = None,
        reason: str = "",
    ) -> ApprovalRequest:
        """代理人提交带生效区间的授权申请。"""
        if valid_from >= valid_until:
            raise PermissionDeniedException(
                "生效区间不合法：开始时间必须早于结束时间",
                valid_from=valid_from.isoformat(),
                valid_until=valid_until.isoformat(),
            )
        if not actions:
            raise PermissionDeniedException("申请至少包含一个操作")

        req = ApprovalRequest(
            request_id=new_token("REQ"),
            requester=requester,
            subject=subject,
            resource_type=resource_type,
            resource_id=resource_id,
            actions=list(actions),
            valid_from=valid_from,
            valid_until=valid_until,
            on_behalf_of=on_behalf_of,
            reason=reason,
        )
        self.repo.save_request(req)
        self.repo.audit.record(
            "request_submitted",
            actor=requester,
            subject=subject,
            resource_type=resource_type,
            resource_id=resource_id,
            summary=f"{requester} 为 {subject} 申请 {resource_type.value}:{resource_id} "
            f"[{','.join(a.value for a in actions)}] {valid_from}~{valid_until}",
            payload={"request_id": req.request_id, "reason": reason},
        )
        return req

    def withdraw_request(self, request_id: str, actor: str) -> ApprovalRequest:
        """申请人在决定做出前撤回申请。"""
        req = self.repo.get_request(request_id)
        if req is None:
            raise PermissionDeniedException("申请不存在", request_id=request_id)
        if actor not in (req.requester, req.subject):
            raise PermissionDeniedException(
                "只有申请人或被授权人可以撤回申请",
                request_id=request_id,
                actor=actor,
            )
        if req.status != RequestStatus.PENDING:
            raise PermissionDeniedException(
                f"申请状态为 {req.status.value}，无法撤回",
                request_id=request_id,
            )

        def _change():
            req.status = RequestStatus.WITHDRAWN
            req.decided_at = utcnow()
            self.repo.save_request(req)

        self.repo.mutate(_change)
        self.repo.audit.record(
            "request_withdrawn",
            actor=actor,
            subject=req.subject,
            resource_type=req.resource_type,
            resource_id=req.resource_id,
            summary=f"申请 {request_id} 被 {actor} 撤回",
            payload={"request_id": request_id},
        )
        return req

    # ------------------------------------------------------------------
    # 审批决定
    # ------------------------------------------------------------------
    def approve_request(
        self,
        request_id: str,
        approver: str,
        *,
        note: str = "",
        override_conflict: bool = False,
        at: Optional[datetime] = None,
    ) -> ApprovalGrant:
        """批准人对申请做决定；同目标区间重叠时必须显式裁决。"""
        at = at or utcnow()
        req = self.repo.get_request(request_id)
        if req is None:
            raise PermissionDeniedException("申请不存在", request_id=request_id)
        if req.status != RequestStatus.PENDING:
            raise PermissionDeniedException(
                f"申请状态为 {req.status.value}，无法批准",
                request_id=request_id,
            )
        # 职责分离：批准人不能是申请人或被授权人本人
        if approver in (req.requester, req.subject):
            raise PermissionDeniedException(
                "批准人不得为申请人或被授权人本人",
                request_id=request_id,
                approver=approver,
            )

        conflicts = self._find_conflicting_grants(req, at)

        def _decide():
            if conflicts and not override_conflict:
                req.status = RequestStatus.CONFLICT
                req.decided_at = at
                self.repo.save_request(req)
                self.repo.audit.record(
                    "approval_conflict",
                    actor=approver,
                    subject=req.subject,
                    resource_type=req.resource_type,
                    resource_id=req.resource_id,
                    summary=f"申请 {request_id} 与 {len(conflicts)} 条生效授权冲突，待裁决",
                    payload={
                        "request_id": request_id,
                        "conflicting_grant_ids": [g.grant_id for g in conflicts],
                    },
                    at=at,
                )
                return None

            superseded = []
            if conflicts:
                for g in conflicts:
                    g.status = GrantStatus.SUPERSEDED
                    g.revoked_at = at
                    g.revoke_reason = f"由申请 {request_id} 的冲突裁决取代"
                    self.repo.save_grant(g)
                    self._void_bindings_for_grant(g, at, approver, "conflict_supersede")
                    superseded.append(g.grant_id)

            grant = ApprovalGrant(
                grant_id=new_token("GRANT"),
                request_id=req.request_id,
                approver=approver,
                subject=req.subject,
                resource_type=req.resource_type,
                resource_id=req.resource_id,
                actions=list(req.actions),
                valid_from=req.valid_from,
                valid_until=req.valid_until,
                on_behalf_of=req.on_behalf_of,
                note=note,
                created_at=at,
            )
            req.status = RequestStatus.APPROVED
            req.decided_at = at
            req.grant_id = grant.grant_id
            self.repo.save_grant(grant)
            self.repo.save_request(req)
            self.repo.audit.record(
                "request_approved",
                actor=approver,
                subject=req.subject,
                resource_type=req.resource_type,
                resource_id=req.resource_id,
                summary=f"申请 {request_id} 已批准为授权 {grant.grant_id}",
                payload={
                    "request_id": request_id,
                    "grant_id": grant.grant_id,
                    "valid_from": grant.valid_from.isoformat(),
                    "valid_until": grant.valid_until.isoformat(),
                    "superseded_grants": superseded,
                    "override_conflict": override_conflict,
                },
                at=at,
            )
            return grant

        result = self.repo.mutate(_decide)
        if result is None:
            raise ApprovalConflictException(
                f"申请 {request_id} 与生效授权区间重叠，需显式裁决（override_conflict）",
                request_id=request_id,
                conflicting_grant_ids=[g.grant_id for g in conflicts],
            )
        return result

    def reject_request(
        self, request_id: str, approver: str, *, reason: str = ""
    ) -> ApprovalRequest:
        """批准人拒绝申请，形成可审计决定。"""
        req = self.repo.get_request(request_id)
        if req is None:
            raise PermissionDeniedException("申请不存在", request_id=request_id)
        if req.status != RequestStatus.PENDING:
            raise PermissionDeniedException(
                f"申请状态为 {req.status.value}，无法拒绝",
                request_id=request_id,
            )
        if approver in (req.requester, req.subject):
            raise PermissionDeniedException(
                "批准人不得为申请人或被授权人本人",
                request_id=request_id,
                approver=approver,
            )

        def _change():
            req.status = RequestStatus.REJECTED
            req.decided_at = utcnow()
            req.reject_reason = reason
            self.repo.save_request(req)

        self.repo.mutate(_change)
        self.repo.audit.record(
            "request_rejected",
            actor=approver,
            subject=req.subject,
            resource_type=req.resource_type,
            resource_id=req.resource_id,
            summary=f"申请 {request_id} 被拒绝：{reason}",
            payload={"request_id": request_id, "reason": reason},
        )
        return req

    def resolve_conflict(
        self, request_id: str, approver: str, *, approve_with_override: bool, note: str = ""
    ) -> Any:
        """对处于 CONFLICT 状态的申请给出最终裁决。"""
        req = self.repo.get_request(request_id)
        if req is None:
            raise PermissionDeniedException("申请不存在", request_id=request_id)
        if req.status != RequestStatus.CONFLICT:
            raise PermissionDeniedException(
                f"申请状态为 {req.status.value}，无需冲突裁决",
                request_id=request_id,
            )
        if approve_with_override:
            # 冲突状态重新进入裁决：先回置 PENDING 再走覆盖批准
            req.status = RequestStatus.PENDING
            self.repo.save_request(req)
            return self.approve_request(
                request_id, approver, note=note, override_conflict=True
            )

        def _reject():
            req.status = RequestStatus.REJECTED
            req.decided_at = utcnow()
            req.reject_reason = note or "冲突裁决：维持原授权"
            self.repo.save_request(req)

        self.repo.mutate(_reject)
        self.repo.audit.record(
            "request_rejected",
            actor=approver,
            subject=req.subject,
            resource_type=req.resource_type,
            resource_id=req.resource_id,
            summary=f"冲突申请 {request_id} 裁决拒绝，维持原授权",
            payload={"request_id": request_id, "note": note},
        )
        return req

    # ------------------------------------------------------------------
    # 撤回授权
    # ------------------------------------------------------------------
    def revoke_grant(
        self, grant_id: str, approver: str, *, reason: str = "", at: Optional[datetime] = None
    ) -> ApprovalGrant:
        """批准人提前撤回授权，相关未完成订单绑定立即作废。"""
        at = at or utcnow()
        grant = self.repo.get_grant(grant_id)
        if grant is None:
            raise PermissionDeniedException("授权不存在", grant_id=grant_id)
        if grant.approver != approver:
            raise PermissionDeniedException(
                "只有原批准人可以撤回该授权",
                grant_id=grant_id,
                actor=approver,
            )
        if grant.status != GrantStatus.ACTIVE:
            raise PermissionDeniedException(
                f"授权状态为 {grant.status.value}，无法撤回",
                grant_id=grant_id,
            )

        def _change():
            grant.status = GrantStatus.REVOKED
            grant.revoked_at = at
            grant.revoke_reason = reason
            self.repo.save_grant(grant)
            self._void_bindings_for_grant(grant, at, approver, "grant_revoked")

        self.repo.mutate(_change)
        self.repo.audit.record(
            "grant_revoked",
            actor=approver,
            subject=grant.subject,
            resource_type=grant.resource_type,
            resource_id=grant.resource_id,
            summary=f"授权 {grant_id} 被 {approver} 撤回：{reason}",
            payload={"grant_id": grant_id, "reason": reason},
            at=at,
        )
        return grant

    # ------------------------------------------------------------------
    # 过期清理
    # ------------------------------------------------------------------
    def expire_due(self, at: Optional[datetime] = None) -> Dict[str, int]:
        """把越过生效区间结束时刻的授权/申请标记过期，绑定作废。

        可由定时任务或启动钩子调用；核验路径也会惰性调用，保证不依赖
        调度器也不会让过期授权放行。
        """
        at = at or utcnow()
        expired_grants = 0
        expired_requests = 0
        voided_bindings = 0

        def _sweep():
            nonlocal expired_grants, expired_requests, voided_bindings
            for grant in self.repo.all_grants():
                if grant.status == GrantStatus.ACTIVE and grant.valid_until < at:
                    grant.status = GrantStatus.EXPIRED
                    grant.revoked_at = at
                    grant.revoke_reason = "生效区间结束"
                    self.repo.save_grant(grant)
                    expired_grants += 1
                    voided_bindings += self._void_bindings_for_grant(
                        grant, at, "system", "grant_expired"
                    )
            for req in self.repo.list_requests(statuses=[RequestStatus.PENDING]):
                if req.valid_until < at:
                    req.status = RequestStatus.EXPIRED
                    req.decided_at = at
                    self.repo.save_request(req)
                    expired_requests += 1

        self.repo.mutate(_sweep)
        if expired_grants or expired_requests:
            logger.info(
                "审批过期清理：%d 条授权、%d 条申请过期，%d 个绑定作废",
                expired_grants,
                expired_requests,
                voided_bindings,
            )
            self.repo.audit.record(
                "expiry_sweep",
                actor="system",
                summary=(
                    f"过期清理：{expired_grants} 授权 / {expired_requests} 申请 / "
                    f"{voided_bindings} 绑定"
                ),
                payload={
                    "expired_grants": expired_grants,
                    "expired_requests": expired_requests,
                    "voided_bindings": voided_bindings,
                },
                at=at,
            )
        return {
            "expired_grants": expired_grants,
            "expired_requests": expired_requests,
            "voided_bindings": voided_bindings,
        }

    # ------------------------------------------------------------------
    # 实时核验
    # ------------------------------------------------------------------
    def authorize(
        self, ctx: OperationContext, *, sweep: bool = True
    ) -> PermissionDecision:
        """核验某身份在当前时刻能否执行目标操作。

        每次都重新查询授权状态（而非信任会话缓存），覆盖提交与恢复点。
        带 ``idempotency_key`` 的重复请求直接复用首次决定。
        """
        at = ctx.effective_time()

        if ctx.idempotency_key:
            prior_id = self.repo.get_idempotent(ctx.actor, ctx.idempotency_key)
            if prior_id is not None:
                original = self.repo.get_decision(prior_id)
                if original is not None:
                    replay = PermissionDecision(
                        outcome=original.outcome,
                        reason=f"重复请求，复用决定 {prior_id}",
                        at=at,
                        actor=ctx.actor,
                        action=ctx.action,
                        resource_type=ctx.resource_type,
                        resource_id=ctx.resource_id,
                        on_behalf_of=ctx.on_behalf_of,
                        grant_id=original.grant_id,
                        request_id=original.request_id,
                        idempotency_key=ctx.idempotency_key,
                    )
                    self.repo.record_decision(replay)
                    return replay

        if sweep and ctx.action in SENSITIVE_ACTIONS:
            self.expire_due(at)

        grant = self._find_live_grant(
            actor=ctx.actor,
            action=ctx.action,
            resource_type=ctx.resource_type,
            resource_id=ctx.resource_id,
            on_behalf_of=ctx.on_behalf_of,
            at=at,
            token=ctx.approval_token,
        )

        if grant is not None:
            decision = PermissionDecision(
                outcome=DecisionOutcome.ALLOW,
                reason="授权有效且处于生效区间内",
                at=at,
                actor=ctx.actor,
                action=ctx.action,
                resource_type=ctx.resource_type,
                resource_id=ctx.resource_id,
                on_behalf_of=ctx.on_behalf_of,
                grant_id=grant.grant_id,
                request_id=grant.request_id,
                idempotency_key=ctx.idempotency_key,
            )
        else:
            pending = self._find_pending_request(ctx, at)
            if pending is not None:
                decision = PermissionDecision(
                    outcome=DecisionOutcome.PENDING_APPROVAL,
                    reason=f"存在待审批申请 {pending.request_id}",
                    at=at,
                    actor=ctx.actor,
                    action=ctx.action,
                    resource_type=ctx.resource_type,
                    resource_id=ctx.resource_id,
                    on_behalf_of=ctx.on_behalf_of,
                    request_id=pending.request_id,
                    idempotency_key=ctx.idempotency_key,
                )
            else:
                decision = PermissionDecision(
                    outcome=DecisionOutcome.DENY,
                    reason="无覆盖该操作、资源与生效区间的有效授权",
                    at=at,
                    actor=ctx.actor,
                    action=ctx.action,
                    resource_type=ctx.resource_type,
                    resource_id=ctx.resource_id,
                    on_behalf_of=ctx.on_behalf_of,
                    idempotency_key=ctx.idempotency_key,
                )

        self.repo.record_decision(decision)
        if ctx.idempotency_key:
            self.repo.save_idempotent(ctx.actor, ctx.idempotency_key, decision.decision_id)
        return decision

    def assert_allowed(self, ctx: OperationContext) -> PermissionDecision:
        """核验并在非 ALLOW 时抛出对应异常。"""
        decision = self.authorize(ctx)
        if decision.outcome is DecisionOutcome.ALLOW:
            return decision
        if decision.outcome is DecisionOutcome.PENDING_APPROVAL:
            raise ApprovalPendingException(
                decision.request_id,
                decision.reason,
                action=ctx.action.value,
                resource=f"{ctx.resource_type.value}:{ctx.resource_id}",
            )
        raise PermissionDeniedException(
            decision.reason,
            action=ctx.action.value,
            resource=f"{ctx.resource_type.value}:{ctx.resource_id}",
            actor=ctx.actor,
        )

    def can_read(
        self,
        actor: str,
        resource_type: ResourceType,
        resource_id: str,
        *,
        on_behalf_of: Optional[str] = None,
        at: Optional[datetime] = None,
    ) -> bool:
        """受限数据的当前读取权限：失权后历史数据同样不可读。"""
        decision = self.authorize(
            OperationContext(
                actor=actor,
                action=Action.READ,
                resource_type=resource_type,
                resource_id=resource_id,
                on_behalf_of=on_behalf_of,
                at=at,
            )
        )
        return decision.outcome is DecisionOutcome.ALLOW

    # ------------------------------------------------------------------
    # 敏感订单：提交与恢复两时点核验
    # ------------------------------------------------------------------
    def commit_order(self, ctx: OperationContext, order_id: str) -> tuple[PermissionDecision, OrderBinding]:
        """订单提交时点核验并建立一次性绑定。

        绑定把授权、订单与幂等键钉在一起；同一订单重复提交时幂等返回。
        """
        if ctx.action not in (Action.PLACE_ORDER, Action.CANCEL_ORDER):
            raise PermissionDeniedException(
                "commit_order 仅用于下单/撤单",
                action=ctx.action.value,
            )
        decision = self.assert_allowed(ctx)
        grant = self.repo.get_grant(decision.grant_id)

        # 同一幂等键（无论订单号是否相同）复用首次绑定，杜绝重复绑定
        if ctx.idempotency_key:
            existing = self.repo.find_binding_by_idempotency(
                ctx.actor, ctx.idempotency_key
            )
            if existing is not None:
                return decision, existing
        existing = self.repo.find_binding_by_order(ctx.actor, order_id)
        if existing is not None:
            return decision, existing

        def _bind():
            binding = OrderBinding(
                binding_id=new_token("BIND"),
                grant_id=grant.grant_id,
                request_id=grant.request_id,
                order_id=order_id,
                subject=ctx.actor,
                on_behalf_of=ctx.on_behalf_of,
                idempotency_key=ctx.idempotency_key or new_token("IDEM"),
            )
            self.repo.save_binding(binding)
            self.repo.audit.record(
                "order_bound",
                actor=ctx.actor,
                subject=ctx.actor,
                resource_type=ctx.resource_type,
                resource_id=ctx.resource_id,
                summary=f"订单 {order_id} 绑定授权 {grant.grant_id}",
                payload={
                    "order_id": order_id,
                    "grant_id": grant.grant_id,
                    "binding_id": binding.binding_id,
                },
                at=ctx.effective_time(),
            )
            return binding

        return decision, self.repo.mutate(_bind)

    def mark_order_committed(self, binding: OrderBinding, order_id: str) -> None:
        """适配器受理成功后消费绑定。"""
        def _consume():
            if binding.status == "bound":
                binding.status = "consumed"
                binding.consumed_at = utcnow()
                self.repo.save_binding(binding)

        self.repo.mutate(_consume)
        self.repo.audit.record(
            "order_committed",
            actor=binding.subject,
            subject=binding.subject,
            resource_type=ResourceType.ORDER,
            resource_id=order_id,
            summary=f"订单 {order_id} 已提交并消费绑定 {binding.binding_id}",
            payload={"order_id": order_id, "binding_id": binding.binding_id},
        )

    def void_order_binding(self, binding: OrderBinding, reason: str) -> None:
        """下单被拒/失败时作废绑定，避免凭据被挪用到恢复路径。"""
        def _void():
            binding.status = "void"
            self.repo.save_binding(binding)

        self.repo.mutate(_void)
        self.repo.audit.record(
            "binding_voided",
            actor=binding.subject,
            subject=binding.subject,
            resource_type=ResourceType.ORDER,
            resource_id=binding.order_id,
            summary=f"绑定 {binding.binding_id} 作废：{reason}",
            payload={"binding_id": binding.binding_id, "reason": reason},
        )

    def resume_order(self, ctx: OperationContext, order_id: str) -> PermissionDecision:
        """订单恢复（断线重连/会话恢复）时点重新核验。

        必须存在提交时建立的绑定，且其授权此刻仍然有效；授权被撤回或
        过期后，恢复一律拒绝，旧会话无法继续操作该订单。
        """
        at = ctx.effective_time()
        self.expire_due(at)

        binding = self.repo.find_binding_by_order(ctx.actor, order_id)
        if binding is None or binding.status == "void":
            decision = PermissionDecision(
                outcome=DecisionOutcome.DENY,
                reason="订单缺少有效的提交绑定，拒绝恢复",
                at=at,
                actor=ctx.actor,
                action=ctx.action,
                resource_type=ResourceType.ORDER,
                resource_id=order_id,
                on_behalf_of=ctx.on_behalf_of,
                idempotency_key=ctx.idempotency_key,
            )
            self.repo.record_decision(decision)
            self.repo.audit.record(
                "order_resume_denied",
                actor=ctx.actor,
                subject=ctx.actor,
                resource_type=ResourceType.ORDER,
                resource_id=order_id,
                summary=decision.reason,
                payload={"order_id": order_id},
                at=at,
            )
            return decision

        if ctx.on_behalf_of != binding.on_behalf_of:
            decision = PermissionDecision(
                outcome=DecisionOutcome.DENY,
                reason="恢复身份与提交时的代理归属不一致",
                at=at,
                actor=ctx.actor,
                action=ctx.action,
                resource_type=ResourceType.ORDER,
                resource_id=order_id,
                on_behalf_of=ctx.on_behalf_of,
                binding_id=binding.binding_id,
            )
            self.repo.record_decision(decision)
            return decision

        grant = self.repo.get_grant(binding.grant_id)
        live = (
            grant is not None
            and grant.is_live(at)
            and ctx.action in grant.actions
        )
        if not live:
            decision = PermissionDecision(
                outcome=DecisionOutcome.DENY,
                reason="授权已失效（撤回/过期/被冲突裁决取代），拒绝恢复",
                at=at,
                actor=ctx.actor,
                action=ctx.action,
                resource_type=ResourceType.ORDER,
                resource_id=order_id,
                on_behalf_of=ctx.on_behalf_of,
                grant_id=binding.grant_id,
                binding_id=binding.binding_id,
            )
            self.repo.record_decision(decision)
            self.repo.audit.record(
                "order_resume_denied",
                actor=ctx.actor,
                subject=ctx.actor,
                resource_type=ResourceType.ORDER,
                resource_id=order_id,
                summary=decision.reason,
                payload={"order_id": order_id, "grant_id": binding.grant_id},
                at=at,
            )
            return decision

        reason = "恢复核验通过"
        if binding.status == "consumed":
            reason = "订单此前已提交完成，恢复核验通过"
        decision = PermissionDecision(
            outcome=DecisionOutcome.ALLOW,
            reason=reason,
            at=at,
            actor=ctx.actor,
            action=ctx.action,
            resource_type=ResourceType.ORDER,
            resource_id=order_id,
            on_behalf_of=ctx.on_behalf_of,
            grant_id=grant.grant_id,
            request_id=grant.request_id,
            binding_id=binding.binding_id,
            idempotency_key=ctx.idempotency_key,
        )
        self.repo.record_decision(decision)
        self.repo.audit.record(
            "order_resume_allowed",
            actor=ctx.actor,
            subject=ctx.actor,
            resource_type=ResourceType.ORDER,
            resource_id=order_id,
            summary=reason,
            payload={"order_id": order_id, "grant_id": grant.grant_id},
            at=at,
        )
        return decision

    # ------------------------------------------------------------------
    # 查询辅助
    # ------------------------------------------------------------------
    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        return self.repo.get_request(request_id)

    def get_grant(self, grant_id: str) -> Optional[ApprovalGrant]:
        return self.repo.get_grant(grant_id)

    def list_requests(self, **filters) -> List[ApprovalRequest]:
        return self.repo.list_requests(**filters)

    def list_grants(self, **filters) -> List[ApprovalGrant]:
        return self.repo.list_grants(**filters)

    def list_decisions(self, **filters) -> List[PermissionDecision]:
        return self.repo.list_decisions(**filters)

    def audit_events(self, **filters):
        return self.repo.audit.query(**filters)

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------
    def _find_live_grant(
        self,
        *,
        actor: str,
        action: Action,
        resource_type: ResourceType,
        resource_id: str,
        on_behalf_of: Optional[str],
        at: datetime,
        token: Optional[str],
    ) -> Optional[ApprovalGrant]:
        candidates = self.repo.list_grants(
            subject=actor,
            resource_type=resource_type,
            statuses=[GrantStatus.ACTIVE],
        )
        matches = [
            g
            for g in candidates
            if g.is_live(at)
            and g.covers(action, resource_id, at)
            and g.on_behalf_of == on_behalf_of
        ]
        if token is not None:
            matches = [g for g in matches if g.grant_id == token]
        if not matches:
            return None
        # 最具体的资源（非通配）优先；同等粒度取最晚生效（最近批准）。
        # 分两次稳定排序，避免对 datetime.min（基线授权）调用 timestamp()。
        matches.sort(key=lambda g: g.valid_from, reverse=True)
        matches.sort(key=lambda g: 0 if g.resource_id == resource_id else 1)
        return matches[0]

    def _find_pending_request(self, ctx: OperationContext, at: datetime) -> Optional[ApprovalRequest]:
        pending = self.repo.list_requests(
            subject=ctx.actor,
            resource_type=ctx.resource_type,
            statuses=[RequestStatus.PENDING],
        )
        for req in pending:
            if req.on_behalf_of != ctx.on_behalf_of:
                continue
            if not (req.valid_from <= at <= req.valid_until):
                continue
            if req.resource_id != "*" and req.resource_id != ctx.resource_id:
                continue
            if ctx.action in req.actions:
                return req
        return None

    def _find_conflicting_grants(
        self, req: ApprovalRequest, at: datetime
    ) -> List[ApprovalGrant]:
        """同被授权人/资源/归属、区间重叠且操作相交的生效授权。"""
        active = self.repo.list_grants(
            subject=req.subject,
            resource_type=req.resource_type,
            statuses=[GrantStatus.ACTIVE],
        )
        conflicts = []
        for g in active:
            if g.on_behalf_of != req.on_behalf_of:
                continue
            if g.resource_id != "*" and req.resource_id != "*" and g.resource_id != req.resource_id:
                continue
            if g.valid_from > req.valid_until or req.valid_from > g.valid_until:
                continue
            if not set(g.actions) & set(req.actions):
                continue
            conflicts.append(g)
        return conflicts

    def _void_bindings_for_grant(
        self, grant: ApprovalGrant, at: datetime, actor: str, reason: str
    ) -> int:
        """作废某授权下尚未消费的订单绑定（调用方需持锁）。"""
        count = 0
        # 绑定数量有限，遍历仓储快照；RLock 可重入，此方法只在 mutate 内调用。
        for binding in self.repo.all_bindings():
            if binding.grant_id == grant.grant_id and binding.status == "bound":
                binding.status = "void"
                binding.consumed_at = at
                self.repo.save_binding(binding)
                count += 1
                self.repo.audit.record(
                    "binding_voided",
                    actor=actor,
                    subject=binding.subject,
                    resource_type=ResourceType.ORDER,
                    resource_id=binding.order_id,
                    summary=f"授权 {grant.grant_id} 失效，绑定 {binding.binding_id} 作废（{reason}）",
                    payload={"binding_id": binding.binding_id, "reason": reason},
                    at=at,
                )
        return count
