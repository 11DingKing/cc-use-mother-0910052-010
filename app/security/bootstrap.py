"""基线授权装配。

现有接口与测试以无身份方式访问，系统初始化时放入一条不生效区间受限
的基线授权（兼容主体），仅覆盖未携带身份头的旧调用。新团队接入后应
携带明确身份并走带生效区间的审批，基线授权可由管理端撤回。
"""

from __future__ import annotations

from datetime import datetime

from app.security.models import (
    Action,
    ApprovalGrant,
    ApprovalRequest,
    GrantStatus,
    RequestStatus,
    ResourceType,
    new_token,
)
from app.security.context import BOOTSTRAP_APPROVER, BOOTSTRAP_PRINCIPAL

_ALL_ACTIONS = [
    Action.READ,
    Action.CREATE,
    Action.UPDATE,
    Action.DELETE,
    Action.EXECUTE,
    Action.PLACE_ORDER,
    Action.CANCEL_ORDER,
]


def install_bootstrap_grants(approval_service) -> list:
    """为兼容主体安装每个资源域的基线授权，返回授权列表。"""
    now = datetime.utcnow()
    grants = []
    for resource_type in ResourceType:
        request_id = new_token("REQ")
        req = ApprovalRequest(
            request_id=request_id,
            requester=BOOTSTRAP_APPROVER,
            subject=BOOTSTRAP_PRINCIPAL,
            resource_type=resource_type,
            resource_id="*",
            actions=list(_ALL_ACTIONS),
            valid_from=datetime.min,
            valid_until=datetime.max,
            reason="系统初始化基线授权，兼容无身份旧调用",
            status=RequestStatus.APPROVED,
            created_at=now,
            decided_at=now,
        )
        grant = ApprovalGrant(
            grant_id=new_token("GRANT"),
            request_id=request_id,
            approver=BOOTSTRAP_APPROVER,
            subject=BOOTSTRAP_PRINCIPAL,
            resource_type=resource_type,
            resource_id="*",
            actions=list(_ALL_ACTIONS),
            valid_from=datetime.min,
            valid_until=datetime.max,
            status=GrantStatus.ACTIVE,
            note="bootstrap",
            created_at=now,
        )
        req.grant_id = grant.grant_id
        approval_service.repo.save_request(req)
        approval_service.repo.save_grant(grant)
        grants.append(grant)
    return grants
