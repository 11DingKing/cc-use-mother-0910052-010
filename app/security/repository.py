"""审批权限的内存仓储与审计台账。

项目默认在单容器内离线运行（SQLite/内存替身），仓储用线程安全的内存
实现即可满足业务路径与异常路径测试；所有状态变更都经同一把锁串行化，
保证撤回、冲突审批与过期清理不会产生竞态决定。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.security.models import (
    ApprovalGrant,
    ApprovalRequest,
    GrantStatus,
    OrderBinding,
    PermissionDecision,
    RequestStatus,
    ResourceType,
    ThreadSafeStore,
    new_token,
    utcnow,
)


@dataclass
class AuditEvent:
    """审计台账中的一条不可变事件。"""

    event_type: str
    at: datetime
    actor: str
    subject: Optional[str] = None
    resource_type: Optional[ResourceType] = None
    resource_id: Optional[str] = None
    summary: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: new_token("AUD"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "at": self.at.isoformat(),
            "actor": self.actor,
            "subject": self.subject,
            "resource_type": self.resource_type.value if self.resource_type else None,
            "resource_id": self.resource_id,
            "summary": self.summary,
            "payload": self.payload,
        }


class ApprovalRepository(ThreadSafeStore):
    """申请、授权、订单绑定、核验结论与幂等记录的仓储。"""

    def __init__(self) -> None:
        super().__init__()
        self._requests: Dict[str, ApprovalRequest] = {}
        self._grants: Dict[str, ApprovalGrant] = {}
        self._bindings: Dict[str, OrderBinding] = {}
        self._decisions: Dict[str, PermissionDecision] = {}
        self._idempotency: Dict[Tuple[str, str], str] = {}
        self.audit = AuditLog()

    # ------------------------------------------------------------------
    # 申请
    # ------------------------------------------------------------------
    def save_request(self, req: ApprovalRequest) -> None:
        with self._lock:
            self._requests[req.request_id] = req

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            return self._requests.get(request_id)

    def list_requests(
        self,
        subject: Optional[str] = None,
        resource_type: Optional[ResourceType] = None,
        statuses: Optional[List[RequestStatus]] = None,
    ) -> List[ApprovalRequest]:
        with self._lock:
            items = list(self._requests.values())
        if subject is not None:
            items = [r for r in items if r.subject == subject]
        if resource_type is not None:
            items = [r for r in items if r.resource_type == resource_type]
        if statuses is not None:
            items = [r for r in items if r.status in statuses]
        return sorted(items, key=lambda r: r.created_at)

    # ------------------------------------------------------------------
    # 授权
    # ------------------------------------------------------------------
    def save_grant(self, grant: ApprovalGrant) -> None:
        with self._lock:
            self._grants[grant.grant_id] = grant

    def get_grant(self, grant_id: str) -> Optional[ApprovalGrant]:
        with self._lock:
            return self._grants.get(grant_id)

    def find_grant_by_request(self, request_id: str) -> Optional[ApprovalGrant]:
        with self._lock:
            for g in self._grants.values():
                if g.request_id == request_id:
                    return g
            return None

    def list_grants(
        self,
        subject: Optional[str] = None,
        resource_type: Optional[ResourceType] = None,
        resource_id: Optional[str] = None,
        statuses: Optional[List[GrantStatus]] = None,
    ) -> List[ApprovalGrant]:
        with self._lock:
            items = list(self._grants.values())
        if subject is not None:
            items = [g for g in items if g.subject == subject]
        if resource_type is not None:
            items = [g for g in items if g.resource_type == resource_type]
        if resource_id is not None:
            items = [
                g
                for g in items
                if g.resource_id == "*" or g.resource_id == resource_id
            ]
        if statuses is not None:
            items = [g for g in items if g.status in statuses]
        return sorted(items, key=lambda g: g.valid_from)

    def all_grants(self) -> List[ApprovalGrant]:
        with self._lock:
            return list(self._grants.values())

    # ------------------------------------------------------------------
    # 订单绑定
    # ------------------------------------------------------------------
    def save_binding(self, binding: OrderBinding) -> None:
        with self._lock:
            self._bindings[binding.binding_id] = binding

    def get_binding(self, binding_id: str) -> Optional[OrderBinding]:
        with self._lock:
            return self._bindings.get(binding_id)

    def find_binding_by_order(
        self, subject: str, order_id: str
    ) -> Optional[OrderBinding]:
        with self._lock:
            for b in self._bindings.values():
                if b.subject == subject and b.order_id == order_id:
                    return b
            return None

    def find_binding_by_idempotency(
        self, subject: str, key: str
    ) -> Optional[OrderBinding]:
        """返回该幂等键的有效绑定；仅存在已作废绑定时返回 None（允许重试）。"""
        with self._lock:
            for b in self._bindings.values():
                if (
                    b.subject == subject
                    and b.idempotency_key == key
                    and b.status != "void"
                ):
                    return b
            return None

    def all_bindings(self) -> List[OrderBinding]:
        with self._lock:
            return list(self._bindings.values())

    # ------------------------------------------------------------------
    # 核验结论
    # ------------------------------------------------------------------
    def record_decision(self, decision: PermissionDecision) -> None:
        with self._lock:
            self._decisions[decision.decision_id] = decision

    def get_decision(self, decision_id: str) -> Optional[PermissionDecision]:
        with self._lock:
            return self._decisions.get(decision_id)

    def list_decisions(
        self,
        actor: Optional[str] = None,
        resource_type: Optional[ResourceType] = None,
        resource_id: Optional[str] = None,
    ) -> List[PermissionDecision]:
        with self._lock:
            items = list(self._decisions.values())
        if actor is not None:
            items = [d for d in items if d.actor == actor]
        if resource_type is not None:
            items = [d for d in items if d.resource_type == resource_type]
        if resource_id is not None:
            items = [d for d in items if d.resource_id == resource_id]
        return sorted(items, key=lambda d: d.at)

    # ------------------------------------------------------------------
    # 幂等
    # ------------------------------------------------------------------
    def get_idempotent(self, subject: str, key: str) -> Optional[str]:
        """返回该幂等键首次命中的决定 ID。"""
        with self._lock:
            return self._idempotency.get((subject, key))

    def save_idempotent(self, subject: str, key: str, decision_id: str) -> bool:
        """登记幂等键；若已存在返回 False（调用方应复用旧决定）。"""
        with self._lock:
            existing = self._idempotency.get((subject, key))
            if existing is not None:
                return False
            self._idempotency[(subject, key)] = decision_id
            return True

    def mutate(self, fn: Callable[[], Any]) -> Any:
        """在仓储锁内执行复合变更，保证决定与台账一致。"""
        with self._lock:
            return fn()


class AuditLog(ThreadSafeStore):
    """只增不改的审计台账。"""

    def __init__(self) -> None:
        super().__init__()
        self._events: List[AuditEvent] = []

    def record(
        self,
        event_type: str,
        actor: str,
        summary: str,
        *,
        subject: Optional[str] = None,
        resource_type: Optional[ResourceType] = None,
        resource_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        at: Optional[datetime] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            at=at or utcnow(),
            actor=actor,
            subject=subject,
            resource_type=resource_type,
            resource_id=resource_id,
            summary=summary,
            payload=payload or {},
        )
        with self._lock:
            self._events.append(event)
        return event

    def query(
        self,
        event_type: Optional[str] = None,
        subject: Optional[str] = None,
        resource_type: Optional[ResourceType] = None,
    ) -> List[AuditEvent]:
        with self._lock:
            events = list(self._events)
        if event_type is not None:
            events = [e for e in events if e.event_type == event_type]
        if subject is not None:
            events = [e for e in events if e.subject == subject]
        if resource_type is not None:
            events = [e for e in events if e.resource_type == resource_type]
        return list(events)
