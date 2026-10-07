"""业务模块说明。"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.services.trading_service import TradingService
from app.security.context import PrincipalContext, resolve_principal

router = APIRouter(prefix="/api/trading", tags=["trading"])
trading_service = TradingService()


class ConnectRequest(BaseModel):
    """业务模块说明。"""
    adapter_type: str = "simulation"  # simulation, vnpy
    config: Optional[dict] = None


class BuyRequest(BaseModel):
    """业务模块说明。"""
    stock_code: str
    quantity: int
    price: Optional[float] = None
    order_type: str = "limit"  # limit, market
    signal_type: Optional[str] = None
    signal_strength: float = 0.0


class SellRequest(BaseModel):
    """业务模块说明。"""
    stock_code: str
    quantity: int
    price: Optional[float] = None
    order_type: str = "limit"  # limit, market
    signal_type: Optional[str] = None
    signal_strength: float = 0.0


class SignalTradeRequest(BaseModel):
    """业务模块说明。"""
    stock_code: str
    signal_type: str
    signal_strength: float
    price: float
    position_ratio: float = 0.1


@router.post("/connect")
async def connect(request: ConnectRequest, principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    success = trading_service.connect(
        request.adapter_type, request.config, principal=principal
    )
    return {
        "success": success,
        "adapter_type": request.adapter_type,
        "message": "连接成功" if success else "连接失败",
    }


@router.post("/disconnect")
async def disconnect(principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    trading_service.disconnect(principal=principal)
    return {"success": True, "message": "已断开连接"}


@router.get("/account")
async def get_account(principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    return trading_service.get_account(principal=principal)


@router.get("/positions")
async def get_positions(principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    return {"positions": trading_service.get_positions(principal=principal)}


@router.get("/positions/{stock_code}")
async def get_position(stock_code: str, principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    position = trading_service.get_position(stock_code, principal=principal)
    if not position:
        return {"error": "未持有该股票"}
    return position


@router.post("/buy")
async def buy(request: BuyRequest, principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    return trading_service.buy(
        stock_code=request.stock_code,
        quantity=request.quantity,
        price=request.price,
        order_type=request.order_type,
        signal_type=request.signal_type,
        signal_strength=request.signal_strength,
        principal=principal,
    )


@router.post("/sell")
async def sell(request: SellRequest, principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    return trading_service.sell(
        stock_code=request.stock_code,
        quantity=request.quantity,
        price=request.price,
        order_type=request.order_type,
        signal_type=request.signal_type,
        signal_strength=request.signal_strength,
        principal=principal,
    )


@router.post("/orders/{order_id}/resume")
async def resume_order(order_id: str, principal: PrincipalContext = Depends(resolve_principal)):
    """订单恢复时点重新核验：授权失效则拒绝旧会话。"""
    return trading_service.resume_order(order_id, principal=principal)


@router.delete("/orders/{order_id}")
async def cancel_order(order_id: str, principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    return trading_service.cancel_order(order_id, principal=principal)


@router.get("/orders/{order_id}")
async def get_order(order_id: str, principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    return trading_service.get_order(order_id, principal=principal)


@router.get("/orders")
async def get_orders(
    stock_code: Optional[str] = Query(default=None, description="股票代码"),
    status: Optional[str] = Query(default=None, description="订单状态"),
    principal: PrincipalContext = Depends(resolve_principal),
):
    """业务模块说明。"""
    return {"orders": trading_service.get_orders(stock_code, status, principal=principal)}


@router.get("/quote/{stock_code}")
async def get_quote(stock_code: str):
    """行情不属于受限数据，无需审批核验。"""
    return trading_service.get_quote(stock_code)


@router.post("/signal-trade")
async def execute_signal_trade(
    request: SignalTradeRequest, principal: PrincipalContext = Depends(resolve_principal)
):
    """业务模块说明。"""
    result = trading_service.execute_signal(
        stock_code=request.stock_code,
        signal_type=request.signal_type,
        signal_strength=request.signal_strength,
        price=request.price,
        position_ratio=request.position_ratio,
        principal=principal,
    )

    if result:
        return result
    return {"message": "自动交易未启用或条件不满足"}


@router.post("/auto-trade/enable")
async def enable_auto_trade(principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    trading_service.enable_auto_trade(True, principal=principal)
    return {"success": True, "message": "自动交易已启用"}


@router.post("/auto-trade/disable")
async def disable_auto_trade(principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    trading_service.enable_auto_trade(False, principal=principal)
    return {"success": True, "message": "自动交易已禁用"}


@router.post("/check-stop-loss")
async def check_stop_loss(principal: PrincipalContext = Depends(resolve_principal)):
    """业务模块说明。"""
    results = trading_service.check_stop_loss_take_profit(principal=principal)
    return {
        "triggered_count": len(results),
        "orders": results,
    }
