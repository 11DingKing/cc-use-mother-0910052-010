"""审批管理接口。

覆盖申请、撤回、批准/拒绝、冲突裁决、授权撤回、过期清理、决定与审计
查询。批准人身份通过 X-Approver-Id 头传递（与操作人 X-Operator-Id
分离，落实职责分离：批准人不能批准自己的申请）。
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel

from app.security.context import PrincipalContext, get_registry, resolve_principal
from app.security.models import Action, RequestStatus, ResourceType

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------
class SubmitRequestModel(BaseModel):
    """代理人提交授权申请。"""

    requester: str
    subject: str
    resource_type: ResourceType
    actions: List[Action]
    valid_from: datetime
    valid_until: datetime
    resource_id: str = "*"
    on_behalf_of: Optional[str] = None
    reason: str = ""


class DecideModel(BaseModel):
    """批准/拒绝。"""

    note: str = ""
    reason: str = ""
    override_conflict: bool = False


class ConflictResolveModel(BaseModel):
    """冲突裁决。"""

    approve_with_override: bool
    note: str = ""


class RevokeModel(BaseModel):
    """撤回授权。"""

    reason: str = ""


# ---------------------------------------------------------------------------
# 审批人身份依赖（与操作人分离）
# ---------------------------------------------------------------------------
def resolve_approver(
    x_approver_id: Optional[str] = Header(default=None, alias="X-Approver-Id"),
) -> str:
    if not x_approver_id:
        # 审批接口必须显式携带批准人身份
        from app.security.exceptions import PermissionDeniedException

        raise PermissionDeniedException("审批操作必须携带 X-Approver-Id 头")
    return x_approver_id


# ---------------------------------------------------------------------------
# 申请与撤回（代理人侧）
# ---------------------------------------------------------------------------
@router.post("/requests")
async def submit_request(body: SubmitRequestModel):
    """代理人提交带生效区间的授权申请。"""
    svc = get_registry().approval_service
    req = svc.submit_request(
        requester=body.requester,
        subject=body.subject,
        resource_type=body.resource_type,
        actions=body.actions,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        resource_id=body.resource_id,
        on_behalf_of=body.on_behalf_of,
        reason=body.reason,
    )
    return req.to_dict()


@router.post("/requests/{request_id}/withdraw")
async def withdraw_request(request_id: str, principal: PrincipalContext = Depends(resolve_principal)):
    """申请人/被授权人在决定前撤回申请。"""
    svc = get_registry().approval_service
    req = svc.withdraw_request(request_id, principal.actor)
    return req.to_dict()


# ---------------------------------------------------------------------------
# 审批决定（批准人侧）
# ---------------------------------------------------------------------------
@router.post("/requests/{request_id}/approve")
async def approve_request(
    request_id: str,
    body: DecideModel,
    approver: str = Depends(resolve_approver),
):
    """批准申请；区间冲突时返回 409，要求显式裁决。"""
    svc = get_registry().approval_service
    grant = svc.approve_request(
        request_id,
        approver,
        note=body.note,
        override_conflict=body.override_conflict,
    )
    return grant.to_dict()


@router.post("/requests/{request_id}/reject")
async def reject_request(
    request_id: str,
    body: DecideModel,
    approver: str = Depends(resolve_approver),
):
    """拒绝申请。"""
    svc = get_registry().approval_service
    req = svc.reject_request(request_id, approver, reason=body.reason)
    return req.to_dict()


@router.post("/requests/{request_id}/resolve-conflict")
async def resolve_conflict(
    request_id: str,
    body: ConflictResolveModel,
    approver: str = Depends(resolve_approver),
):
    """对冲突申请给出最终裁决：覆盖批准或维持原授权。"""
    svc = get_registry().approval_service
    result = svc.resolve_conflict(
        request_id, approver, approve_with_override=body.approve_with_override, note=body.note
    )
    return result.to_dict()


@router.post("/grants/{grant_id}/revoke")
async def revoke_grant(
    grant_id: str,
    body: RevokeModel,
    approver: str = Depends(resolve_approver),
):
    """原批准人提前撤回授权。"""
    svc = get_registry().approval_service
    grant = svc.revoke_grant(grant_id, approver, reason=body.reason)
    return grant.to_dict()


# ---------------------------------------------------------------------------
# 过期清理（可由定时器调用）
# ---------------------------------------------------------------------------
@router.post("/expire-sweep")
async def expire_sweep(approver: str = Depends(resolve_approver)):
    """清理越过生效区间的授权/申请，并作废相关订单绑定。"""
    svc = get_registry().approval_service
    return svc.expire_due()


# ---------------------------------------------------------------------------
# 查询（审计与决定留痕）
# ---------------------------------------------------------------------------
@router.get("/requests")
async def list_requests(
    subject: Optional[str] = Query(default=None),
    resource_type: Optional[ResourceType] = Query(default=None),
    status: Optional[RequestStatus] = Query(default=None),
    approver: str = Depends(resolve_approver),
):
    """查询审批申请。"""
    svc = get_registry().approval_service
    statuses = [status] if status else None
    items = svc.list_requests(
        subject=subject, resource_type=resource_type, statuses=statuses
    )
    return {"count": len(items), "requests": [r.to_dict() for r in items]}


@router.get("/grants")
async def list_grants(
    subject: Optional[str] = Query(default=None),
    resource_type: Optional[ResourceType] = Query(default=None),
    resource_id: Optional[str] = Query(default=None),
    approver: str = Depends(resolve_approver),
):
    """查询授权。"""
    svc = get_registry().approval_service
    items = svc.list_grants(
        subject=subject, resource_type=resource_type, resource_id=resource_id
    )
    return {"count": len(items), "grants": [g.to_dict() for g in items]}


@router.get("/decisions")
async def list_decisions(
    actor: Optional[str] = Query(default=None),
    resource_type: Optional[ResourceType] = Query(default=None),
    approver: str = Depends(resolve_approver),
):
    """查询历次权限核验决定（含拒绝/待批，供审计）。"""
    svc = get_registry().approval_service
    items = svc.list_decisions(actor=actor, resource_type=resource_type)
    return {"count": len(items), "decisions": [d.to_dict() for d in items]}


@router.get("/audit")
async def list_audit(
    event_type: Optional[str] = Query(default=None),
    subject: Optional[str] = Query(default=None),
    resource_type: Optional[ResourceType] = Query(default=None),
    approver: str = Depends(resolve_approver),
):
    """查询不可变审计台账。"""
    svc = get_registry().approval_service
    items = svc.audit_events(
        event_type=event_type, subject=subject, resource_type=resource_type
    )
    return {"count": len(items), "events": [e.to_dict() for e in items]}
