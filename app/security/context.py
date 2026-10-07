"""操作身份上下文与进程内单例装配。

HTTP 层通过请求头解析操作身份；服务层也可直接构造 ``PrincipalContext``。
审批服务、操作台账与交易服务共享同一进程内单例，保证下单时写入的留痕
与审批管理接口读到的是同一份决定数据。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Header

from app.security.approval_service import ApprovalService
from app.security.ledger import OperationLedger

# 未携带身份头时的兼容主体（系统初始化基线授权覆盖，见 bootstrap）。
BOOTSTRAP_PRINCIPAL = "legacy-system"
BOOTSTRAP_APPROVER = "bootstrap-admin"


@dataclass(frozen=True)
class PrincipalContext:
    """一次请求的操作身份。"""

    actor: str
    on_behalf_of: Optional[str] = None
    idempotency_key: Optional[str] = None
    approval_token: Optional[str] = None

    @property
    def is_bootstrap(self) -> bool:
        return self.actor == BOOTSTRAP_PRINCIPAL


def resolve_principal(
    x_operator_id: Optional[str] = Header(default=None, alias="X-Operator-Id"),
    x_on_behalf_of: Optional[str] = Header(default=None, alias="X-On-Behalf-Of"),
    x_idempotency_key: Optional[str] = Header(default=None, alias="X-Idempotency-Key"),
    x_approval_token: Optional[str] = Header(default=None, alias="X-Approval-Token"),
) -> PrincipalContext:
    """FastAPI 依赖：从请求头解析身份，缺省回落为基线兼容主体。"""
    return PrincipalContext(
        actor=x_operator_id or BOOTSTRAP_PRINCIPAL,
        on_behalf_of=x_on_behalf_of,
        idempotency_key=x_idempotency_key,
        approval_token=x_approval_token,
    )


class SecurityRegistry:
    """审批服务与操作台账的进程内单例。"""

    def __init__(self, install_bootstrap: bool = True) -> None:
        self.approval_service = ApprovalService()
        self.operation_ledger = OperationLedger(self.approval_service)
        if install_bootstrap:
            from app.security.bootstrap import install_bootstrap_grants

            install_bootstrap_grants(self.approval_service)

    def reset(self) -> None:
        """测试辅助：清空全部审批状态与台账。"""
        self.approval_service = ApprovalService()
        self.operation_ledger = OperationLedger(self.approval_service)


_registry: Optional[SecurityRegistry] = None


def get_registry() -> SecurityRegistry:
    global _registry
    if _registry is None:
        _registry = SecurityRegistry()
    return _registry


def reset_registry(install_bootstrap: bool = True) -> SecurityRegistry:
    """重置单例（测试使用）。"""
    global _registry
    _registry = SecurityRegistry(install_bootstrap=install_bootstrap)
    return _registry
