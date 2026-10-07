"""受限操作台账：留痕执行人与批准人，并按当前权限过滤历史数据。

历史记录（订单、组合快照、策略动作等）创建时固化当时的执行人
（executor）与批准人（approver）。之后查询时：

* 读权限按查询时刻重新核验——后来失权的人读不到受限数据；
* 返回记录保留原始执行人/批准人，不因后来授权变化而改写历史。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.security.models import ResourceType, utcnow


@dataclass
class LedgerRecord:
    """一条受限资源的执行留痕。"""

    record_id: str
    resource_type: ResourceType
    resource_id: str
    executor: str                       # 当时的实际执行人
    approver: Optional[str]             # 当时的批准人
    on_behalf_of: Optional[str]
    grant_id: Optional[str]
    request_id: Optional[str]
    action: str
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "resource_type": self.resource_type.value,
            "resource_id": self.resource_id,
            "executor": self.executor,
            "approver": self.approver,
            "on_behalf_of": self.on_behalf_of,
            "grant_id": self.grant_id,
            "request_id": self.request_id,
            "action": self.action,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
        }


class OperationLedger:
    """受限操作的留痕与读过滤。"""

    def __init__(self, approval_service) -> None:
        self.approvals = approval_service
        self._records: Dict[str, LedgerRecord] = {}
        self._lock = threading.RLock()

    def record(
        self,
        *,
        resource_type: ResourceType,
        resource_id: str,
        executor: str,
        action: str,
        decision=None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> LedgerRecord:
        """固化一次受限操作；批准人取自核验所依据的授权。"""
        import uuid

        approver = None
        grant_id = None
        request_id = None
        on_behalf_of = None
        if decision is not None:
            grant_id = decision.grant_id
            request_id = decision.request_id
            on_behalf_of = decision.on_behalf_of
            if grant_id:
                grant = self.approvals.repo.get_grant(grant_id)
                approver = grant.approver if grant else None

        record = LedgerRecord(
            record_id=f"LED_{uuid.uuid4().hex}",
            resource_type=resource_type,
            resource_id=resource_id,
            executor=executor,
            approver=approver,
            on_behalf_of=on_behalf_of,
            grant_id=grant_id,
            request_id=request_id,
            action=action,
            payload=payload or {},
        )
        with self._lock:
            self._records[record.record_id] = record
        return record

    def list_for(self, resource_type: ResourceType, resource_id: str) -> List[LedgerRecord]:
        """管理/审计视角：某资源的全部留痕（不做读过滤）。"""
        with self._lock:
            records = [
                r
                for r in self._records.values()
                if r.resource_type == resource_type and r.resource_id == resource_id
            ]
        return sorted(records, key=lambda r: r.created_at)

    def visible_to(
        self,
        actor: str,
        resource_type: ResourceType,
        *,
        on_behalf_of: Optional[str] = None,
        at: Optional[datetime] = None,
    ) -> List[LedgerRecord]:
        """执行人视角：仅返回其此刻仍有 READ 权限的资源留痕。

        对每条不同资源都实时核验；失权后该资源的历史立刻不可见。
        执行人本人过去留下的记录也不例外——读权限取决于"现在"。
        """
        with self._lock:
            candidates = [
                r for r in self._records.values() if r.resource_type == resource_type
            ]

        visible: List[LedgerRecord] = []
        checked: Dict[str, bool] = {}
        for r in candidates:
            if r.resource_id not in checked:
                checked[r.resource_id] = self.approvals.can_read(
                    actor,
                    resource_type,
                    r.resource_id,
                    on_behalf_of=on_behalf_of,
                    at=at,
                )
            if checked[r.resource_id]:
                visible.append(r)
        return sorted(visible, key=lambda r: r.created_at)

    def annotate(self, data: Dict[str, Any], record: LedgerRecord) -> Dict[str, Any]:
        """把执行人/批准人注入返回给接口的数据，保留历史现场。"""
        data = dict(data)
        data["executor"] = record.executor
        data["approver"] = record.approver
        data["executed_on_behalf_of"] = record.on_behalf_of
        data["grant_id"] = record.grant_id
        return data
