"""审批权限领域模型。

研究账户与实盘账户由不同团队维护后，仅按登录身份粗略放行无法满足
"临时授权到期即失权"的要求。本模块用四类对象描述审批链路：

* ApprovalRequest：代理人发起的授权申请（含生效区间、目标资源与操作）。
* ApprovalGrant：批准人对申请做出的批准/拒绝/撤回决定，是运行时核验依据。
* OrderBinding：批准与具体订单的绑定（一次性凭据 + 幂等键）。
* PermissionDecision / OperationContext：每次敏感操作核验的输入与可审计结论。
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

WILDCARD_ACTION = "*"
_OPEN_ENDED = datetime.max


def utcnow() -> datetime:
    """统一的时间源，便于测试注入。"""
    return datetime.utcnow()


def new_token(prefix: str) -> str:
    """生成不可猜测的审批/绑定令牌。"""
    return f"{prefix}_{uuid.uuid4().hex}"


class ResourceType(str, Enum):
    """受限资源域：账户、组合、策略、订单。"""

    ACCOUNT = "account"
    PORTFOLIO = "portfolio"
    STRATEGY = "strategy"
    ORDER = "order"


class Action(str, Enum):
    """资源上的操作。READ 为受限读，其余为敏感写/执行操作。"""

    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"      # 账户连接、策略启停
    PLACE_ORDER = "place_order"
    CANCEL_ORDER = "cancel_order"


# 敏感操作集合：提交与恢复时都必须重新核验
SENSITIVE_ACTIONS = frozenset(
    {
        Action.CREATE,
        Action.UPDATE,
        Action.DELETE,
        Action.EXECUTE,
        Action.PLACE_ORDER,
        Action.CANCEL_ORDER,
    }
)


class RequestStatus(str, Enum):
    """审批申请状态。"""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONFLICT = "conflict"      # 与生效区间重叠的同目标批准冲突
    WITHDRAWN = "withdrawn"    # 申请人在批准前撤回
    EXPIRED = "expired"        # 生效区间结束或清理任务标记过期


class GrantStatus(str, Enum):
    """批准授权状态。"""

    ACTIVE = "active"
    REVOKED = "revoked"        # 批准人撤回
    SUPERSEDED = "superseded"  # 被冲突审批处理置为失效
    EXPIRED = "expired"        # 越过生效区间结束时刻


class DecisionOutcome(str, Enum):
    """核验结论。"""

    ALLOW = "allow"
    DENY = "deny"
    PENDING_APPROVAL = "pending_approval"


@dataclass(frozen=True)
class OperationContext:
    """一次敏感/受限操作的核验输入。

    ``actor`` 为登录身份；``on_behalf_of`` 为被代理的账户属主，
    二者相同表示本人操作。``idempotency_key`` 用于重复请求去重。
    """

    actor: str
    action: Action
    resource_type: ResourceType
    resource_id: str = "*"
    on_behalf_of: Optional[str] = None
    idempotency_key: Optional[str] = None
    order_id: Optional[str] = None
    approval_token: Optional[str] = None
    at: Optional[datetime] = None

    def effective_time(self) -> datetime:
        return self.at or utcnow()

    def principal(self) -> str:
        """操作实际归属人：代理人场景下为被代理属主。"""
        return self.on_behalf_of or self.actor


@dataclass
class ApprovalGrant:
    """一条带生效区间的批准授权。"""

    grant_id: str
    request_id: str
    approver: str
    subject: str                       # 被授权人（代理人）
    resource_type: ResourceType
    resource_id: str                   # 具体资源标识或 "*"
    actions: List[Action]
    valid_from: datetime
    valid_until: datetime
    status: GrantStatus = GrantStatus.ACTIVE
    on_behalf_of: Optional[str] = None  # 被代理账户属主
    note: str = ""
    created_at: datetime = field(default_factory=utcnow)
    revoked_at: Optional[datetime] = None
    revoke_reason: str = ""

    def covers(self, action: Action, resource_id: str, at: datetime) -> bool:
        """该授权是否在给定时刻覆盖目标操作（忽略状态，状态另判）。"""
        if not (self.valid_from <= at <= self.valid_until):
            return False
        if self.resource_id != WILDCARD_ACTION and self.resource_id != resource_id:
            return False
        if action not in self.actions:
            return False
        return True

    def is_live(self, at: datetime) -> bool:
        """授权当前是否有效：状态为 ACTIVE 且处于生效区间内。"""
        if self.status != GrantStatus.ACTIVE:
            return False
        return self.valid_from <= at <= self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "request_id": self.request_id,
            "approver": self.approver,
            "subject": self.subject,
            "resource_type": self.resource_type.value,
            "resource_id": self.resource_id,
            "actions": [a.value for a in self.actions],
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "status": self.status.value,
            "on_behalf_of": self.on_behalf_of,
            "note": self.note,
            "created_at": self.created_at.isoformat(),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoke_reason": self.revoke_reason,
        }


@dataclass
class ApprovalRequest:
    """代理人提交的授权申请。"""

    request_id: str
    requester: str
    subject: str
    resource_type: ResourceType
    resource_id: str
    actions: List[Action]
    valid_from: datetime
    valid_until: datetime
    on_behalf_of: Optional[str] = None
    reason: str = ""
    status: RequestStatus = RequestStatus.PENDING
    created_at: datetime = field(default_factory=utcnow)
    decided_at: Optional[datetime] = None
    grant_id: Optional[str] = None
    reject_reason: str = ""

    def target_key(self) -> tuple:
        return (
            self.subject,
            self.resource_type,
            self.resource_id,
            self.on_behalf_of,
        )

    def overlaps(self, other: "ApprovalRequest") -> bool:
        """与另一申请的目标和生效区间是否同时重叠。"""
        if self.target_key() != other.target_key():
            return False
        return self.valid_from <= other.valid_until and other.valid_from <= self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "requester": self.requester,
            "subject": self.subject,
            "resource_type": self.resource_type.value,
            "resource_id": self.resource_id,
            "actions": [a.value for a in self.actions],
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "on_behalf_of": self.on_behalf_of,
            "reason": self.reason,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "grant_id": self.grant_id,
            "reject_reason": self.reject_reason,
        }


@dataclass
class OrderBinding:
    """批准与订单的一次性绑定。

    敏感订单提交时凭审批令牌换发绑定；恢复（重放/断线恢复）时必须同时
    校验订单号与绑定状态，防止授权结束后旧会话继续下单。
    """

    binding_id: str
    grant_id: str
    request_id: str
    order_id: str
    subject: str
    on_behalf_of: Optional[str]
    idempotency_key: str
    status: str = "bound"  # bound / consumed / void
    created_at: datetime = field(default_factory=utcnow)
    consumed_at: Optional[datetime] = None

    def is_usable(self, at: datetime) -> bool:
        return self.status == "bound" and self.consumed_at is None


@dataclass(frozen=True)
class PermissionDecision:
    """一次核验的可审计结论。"""

    outcome: DecisionOutcome
    reason: str
    at: datetime
    actor: str
    action: Action
    resource_type: ResourceType
    resource_id: str
    on_behalf_of: Optional[str] = None
    grant_id: Optional[str] = None
    request_id: Optional[str] = None
    binding_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    decision_id: str = field(default_factory=lambda: new_token("DEC"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "outcome": self.outcome.value,
            "reason": self.reason,
            "at": self.at.isoformat(),
            "actor": self.actor,
            "action": self.action.value,
            "resource_type": self.resource_type.value,
            "resource_id": self.resource_id,
            "on_behalf_of": self.on_behalf_of,
            "grant_id": self.grant_id,
            "request_id": self.request_id,
            "binding_id": self.binding_id,
            "idempotency_key": self.idempotency_key,
        }


class ThreadSafeStore:
    """供内存仓储使用的可重入锁混入。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
