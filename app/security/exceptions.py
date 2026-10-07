"""审批权限相关异常。"""

from typing import Any, Dict, Optional

from app.middleware.exception_handler import AppException


class _SecurityException(AppException):
    """审批权限异常基类，统一错误码前缀。"""

    def __init__(
        self,
        message: str,
        code: str,
        status_code: int,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            code=code,
            status_code=status_code,
            details=details or {},
        )


class PermissionDeniedException(_SecurityException):
    """无有效授权（从未批准、已撤回、已过期、资源不匹配）。"""

    def __init__(self, message: str = "权限核验未通过", **details: Any):
        super().__init__(
            message,
            code="PERMISSION_DENIED",
            status_code=403,
            details=details,
        )


class ApprovalPendingException(_SecurityException):
    """操作命中一条尚未批准的申请，敏感操作必须等待批准。"""

    def __init__(self, request_id: str, message: str = "申请尚待审批", **details: Any):
        super().__init__(
            message,
            code="APPROVAL_PENDING",
            status_code=403,
            details={"request_id": request_id, **details},
        )


class ApprovalConflictException(_SecurityException):
    """申请与同目标、生效区间重叠且仍有效的授权/申请冲突。"""

    def __init__(self, message: str = "审批区间冲突", **details: Any):
        super().__init__(
            message,
            code="APPROVAL_CONFLICT",
            status_code=409,
            details=details,
        )
