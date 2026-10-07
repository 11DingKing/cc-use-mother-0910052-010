"""业务模块说明。"""

import logging
import threading
from decimal import Decimal
from typing import Dict, List, Optional, Any, Tuple

from app.trading.base import (
    TradingAdapter,
    Order,
    OrderStatus,
    OrderType,
    OrderSide,
    RiskManager,
)
from app.trading.simulation_adapter import SimulationAdapter
from app.trading.vnpy_adapter import VnpyAdapter
from app.services.analysis_service import AnalysisService
from app.middleware.exception_handler import AppException
from app.security.context import BOOTSTRAP_PRINCIPAL, PrincipalContext, get_registry
from app.security.exceptions import PermissionDeniedException
from app.security.models import Action, OperationContext, ResourceType

logger = logging.getLogger(__name__)


class TradingException(AppException):
    """业务模块说明。"""

    def __init__(
        self,
        message: str,
        order_id: Optional[str] = None,
        stock_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            code="TRADING_ERROR",
            status_code=400,
            details={
                "order_id": order_id,
                "stock_code": stock_code,
                **(details or {}),
            },
        )


class TradingService:
    """交易编排。

    账户、组合、策略与订单操作均经过带生效区间的审批核验：

    * 写/执行类敏感操作（连接、策略启停、下单、撤单）提交时核验；
    * 订单在断线/会话恢复时通过 :meth:`resume_order` 再次核验；
    * 读类操作（账户、持仓、订单查询）每次实时核验，失权后历史不可读；
    * 每次执行在台账固化执行人与批准人，查询时原样带出。
    """

    def __init__(
        self,
        adapter: Optional[TradingAdapter] = None,
        approval_service=None,
        operation_ledger=None,
    ):
        self.adapter = adapter or SimulationAdapter()
        self.risk_manager = RiskManager()
        self.analysis_service = AnalysisService()
        self._auto_trade_enabled = False

        # 显式注入时锁定实例；否则每次经由注册表动态解析，
        # 使进程内重置（测试/重新装配）能被控制器侧立即感知。
        if approval_service is not None or operation_ledger is not None:
            if approval_service is None or operation_ledger is None:
                raise ValueError("approval_service 与 operation_ledger 必须同时提供")
            self._fixed_services = (approval_service, operation_ledger)
            self._registry_getter = None
        else:
            self._fixed_services = None
            self._registry_getter = get_registry

        # 下单幂等：(执行人, 幂等键) -> 首次结果，防止重复请求二次下单
        self._idempotent_orders: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._idem_lock = threading.RLock()

    @property
    def approvals(self):
        """当前生效的审批服务（动态解析或显式注入）。"""
        if self._fixed_services is not None:
            return self._fixed_services[0]
        return self._registry_getter().approval_service

    @property
    def ledger(self):
        """当前生效的操作台账。"""
        if self._fixed_services is not None:
            return self._fixed_services[1]
        return self._registry_getter().operation_ledger

    # ------------------------------------------------------------------
    # 核验辅助
    # ------------------------------------------------------------------
    @staticmethod
    def _principal(principal: Optional[PrincipalContext]) -> PrincipalContext:
        return principal or PrincipalContext(actor=BOOTSTRAP_PRINCIPAL)

    def _context(
        self,
        principal: PrincipalContext,
        action: Action,
        resource_type: ResourceType,
        resource_id: str = "*",
        *,
        with_idempotency: bool = True,
    ) -> OperationContext:
        return OperationContext(
            actor=principal.actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            on_behalf_of=principal.on_behalf_of,
            idempotency_key=principal.idempotency_key if with_idempotency else None,
            approval_token=principal.approval_token,
        )

    def _replayed_order(self, principal: PrincipalContext) -> Optional[Dict[str, Any]]:
        if not principal.idempotency_key:
            return None
        with self._idem_lock:
            hit = self._idempotent_orders.get((principal.actor, principal.idempotency_key))
        return dict(hit) if hit else None

    def _remember_order(self, principal: PrincipalContext, result: Dict[str, Any]) -> None:
        if not principal.idempotency_key:
            return
        with self._idem_lock:
            self._idempotent_orders.setdefault(
                (principal.actor, principal.idempotency_key), dict(result)
            )

    def _annotate_order(self, order_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        records = self.ledger.list_for(ResourceType.ORDER, order_id)
        if records:
            return self.ledger.annotate(data, records[-1])
        return data

    # ------------------------------------------------------------------
    # 账户
    # ------------------------------------------------------------------
    def connect(
        self,
        adapter_type: str = "simulation",
        config: Optional[Dict] = None,
        principal: Optional[PrincipalContext] = None,
    ) -> bool:
        """业务模块说明。"""
        principal = self._principal(principal)
        self.approvals.assert_allowed(
            self._context(principal, Action.EXECUTE, ResourceType.ACCOUNT)
        )

        if adapter_type == "vnpy":
            self.adapter = VnpyAdapter(config or {})
        else:
            self.adapter = SimulationAdapter(config)

        success = self.adapter.connect()
        if success:
            account = self.adapter.get_account()
            self.ledger.record(
                resource_type=ResourceType.ACCOUNT,
                resource_id=account.account_id if account else "*",
                executor=principal.actor,
                action="connect",
                payload={"adapter_type": adapter_type},
            )
        return success

    def disconnect(self, principal: Optional[PrincipalContext] = None) -> None:
        """业务模块说明。"""
        principal = self._principal(principal)
        self.approvals.assert_allowed(
            self._context(principal, Action.EXECUTE, ResourceType.ACCOUNT)
        )
        if self.adapter:
            self.adapter.disconnect()

    def get_account(self, principal: Optional[PrincipalContext] = None) -> Dict[str, Any]:
        """业务模块说明。"""
        principal = self._principal(principal)
        account = self.adapter.get_account()
        if not account:
            raise TradingException("无法获取账户信息，请检查交易连接")

        self.approvals.assert_allowed(
            self._context(
                principal, Action.READ, ResourceType.ACCOUNT, account.account_id
            )
        )
        return account.to_dict()

    # ------------------------------------------------------------------
    # 组合（持仓）
    # ------------------------------------------------------------------
    def get_positions(self, principal: Optional[PrincipalContext] = None) -> List[Dict[str, Any]]:
        """业务模块说明。"""
        principal = self._principal(principal)
        # 组合列表只返回此刻仍有读权限的标的；无权限则为空列表，
        # 不暴露标的是否存在。单只标的查询走 get_position 的显式核验。
        result = []
        for p in self.adapter.get_positions():
            if self.approvals.can_read(
                principal.actor,
                ResourceType.PORTFOLIO,
                p.stock_code,
                on_behalf_of=principal.on_behalf_of,
            ):
                result.append(p.to_dict())
        return result

    def get_position(
        self, stock_code: str, principal: Optional[PrincipalContext] = None
    ) -> Optional[Dict[str, Any]]:
        """业务模块说明。"""
        principal = self._principal(principal)
        self.approvals.assert_allowed(
            self._context(principal, Action.READ, ResourceType.PORTFOLIO, stock_code)
        )
        position = self.adapter.get_position(stock_code)
        return position.to_dict() if position else None

    # ------------------------------------------------------------------
    # 订单（提交与恢复双时点核验）
    # ------------------------------------------------------------------
    def buy(
        self,
        stock_code: str,
        quantity: int,
        price: Optional[float] = None,
        order_type: str = "limit",
        signal_type: Optional[str] = None,
        signal_strength: float = 0.0,
        principal: Optional[PrincipalContext] = None,
    ) -> Dict[str, Any]:
        """业务模块说明。"""
        principal = self._principal(principal)

        # 重复请求：幂等键命中直接返回首次决定，绝不二次下单
        replayed = self._replayed_order(principal)
        if replayed is not None:
            return replayed

        # 数量校验（仅校验请求自身参数，不涉及受限资源）
        if quantity <= 0 or quantity % 100 != 0:
            raise TradingException(
                "买入数量必须是100的整数倍",
                stock_code=stock_code,
            )

        # 构建订单
        ot = OrderType.LIMIT if order_type == "limit" else OrderType.MARKET

        if ot == OrderType.LIMIT and price is None:
            raise TradingException("限价单必须指定价格", stock_code=stock_code)

        order = Order(
            order_id=self.adapter._generate_order_id(),
            stock_code=stock_code,
            side=OrderSide.BUY,
            order_type=ot,
            quantity=quantity,
            price=Decimal(str(price)) if price else None,
            signal_type=signal_type,
            signal_strength=signal_strength,
        )

        # 提交时点核验：授权须此刻有效，并建立订单-授权一次性绑定。
        # 核验先于任何账户/持仓访问，避免向无权者泄露资源信息。
        ctx = self._context(
            principal, Action.PLACE_ORDER, ResourceType.ORDER, stock_code
        )
        decision, binding = self.approvals.commit_order(ctx, order.order_id)

        # 风控检查
        account = self.adapter.get_account()
        positions = self.adapter.get_positions()

        passed, reason = self.risk_manager.check_order(order, account, positions)
        if not passed:
            self.approvals.void_order_binding(binding, f"风控未通过: {reason}")
            raise TradingException(
                f"风控检查未通过: {reason}",
                stock_code=stock_code,
            )

        # 执行下单
        result = self.adapter.place_order(order)

        if result.status in (OrderStatus.REJECTED, OrderStatus.FAILED):
            self.approvals.void_order_binding(
                binding, result.error_message or "下单被拒"
            )
            raise TradingException(
                f"下单失败: {result.error_message}",
                order_id=result.order_id,
                stock_code=stock_code,
            )

        # 受理成功：消费绑定并固化执行人/批准人
        self.approvals.mark_order_committed(binding, order.order_id)
        if result.status == OrderStatus.FILLED:
            self.risk_manager.record_trade(result.filled_price * result.filled_quantity)

        payload = result.to_dict()
        self.ledger.record(
            resource_type=ResourceType.ORDER,
            resource_id=order.order_id,
            executor=principal.actor,
            action="buy",
            decision=decision,
            payload={"stock_code": stock_code, "quantity": quantity},
        )
        payload = self._annotate_order(order.order_id, payload)
        self._remember_order(principal, payload)
        return payload

    def sell(
        self,
        stock_code: str,
        quantity: int,
        price: Optional[float] = None,
        order_type: str = "limit",
        signal_type: Optional[str] = None,
        signal_strength: float = 0.0,
        principal: Optional[PrincipalContext] = None,
    ) -> Dict[str, Any]:
        """业务模块说明。"""
        principal = self._principal(principal)

        replayed = self._replayed_order(principal)
        if replayed is not None:
            return replayed

        # 构建订单
        ot = OrderType.LIMIT if order_type == "limit" else OrderType.MARKET

        if ot == OrderType.LIMIT and price is None:
            raise TradingException("限价单必须指定价格", stock_code=stock_code)

        order = Order(
            order_id=self.adapter._generate_order_id(),
            stock_code=stock_code,
            side=OrderSide.SELL,
            order_type=ot,
            quantity=quantity,
            price=Decimal(str(price)) if price else None,
            signal_type=signal_type,
            signal_strength=signal_strength,
        )

        # 提交时点核验先于持仓访问，避免向无权者泄露持仓信息
        ctx = self._context(
            principal, Action.PLACE_ORDER, ResourceType.ORDER, stock_code
        )
        decision, binding = self.approvals.commit_order(ctx, order.order_id)

        # 持仓检查（核验通过后才读取受限资源）
        position = self.adapter.get_position(stock_code)
        if not position or position.available_quantity < quantity:
            available = position.available_quantity if position else 0
            self.approvals.void_order_binding(
                binding, f"可用持仓不足，需要 {quantity}，可用 {available}"
            )
            raise TradingException(
                f"可用持仓不足，需要 {quantity}，可用 {available}",
                stock_code=stock_code,
            )

        # 执行下单
        result = self.adapter.place_order(order)

        if result.status in (OrderStatus.REJECTED, OrderStatus.FAILED):
            self.approvals.void_order_binding(
                binding, result.error_message or "下单被拒"
            )
            raise TradingException(
                f"下单失败: {result.error_message}",
                order_id=result.order_id,
                stock_code=stock_code,
            )

        self.approvals.mark_order_committed(binding, order.order_id)
        payload = result.to_dict()
        self.ledger.record(
            resource_type=ResourceType.ORDER,
            resource_id=order.order_id,
            executor=principal.actor,
            action="sell",
            decision=decision,
            payload={"stock_code": stock_code, "quantity": quantity},
        )
        payload = self._annotate_order(order.order_id, payload)
        self._remember_order(principal, payload)
        return payload

    def resume_order(
        self, order_id: str, principal: Optional[PrincipalContext] = None
    ) -> Dict[str, Any]:
        """订单恢复时点重新核验：授权失效则拒绝旧会话继续操作。"""
        principal = self._principal(principal)
        ctx = self._context(
            principal, Action.PLACE_ORDER, ResourceType.ORDER, order_id
        )
        decision = self.approvals.resume_order(ctx, order_id)
        if decision.outcome.value != "allow":
            raise PermissionDeniedException(
                decision.reason,
                order_id=order_id,
                actor=principal.actor,
            )
        return decision.to_dict()

    def cancel_order(
        self, order_id: str, principal: Optional[PrincipalContext] = None
    ) -> Dict[str, Any]:
        """业务模块说明。"""
        principal = self._principal(principal)
        order = self.adapter.get_order(order_id)
        if not order:
            raise TradingException("订单不存在", order_id=order_id)

        # 撤单是敏感操作：先核验权限并绑定，再检查订单业务状态
        ctx = self._context(
            principal, Action.CANCEL_ORDER, ResourceType.ORDER, order_id
        )
        decision, binding = self.approvals.commit_order(ctx, order_id)

        if order.status not in (OrderStatus.PENDING, OrderStatus.SUBMITTED):
            self.approvals.void_order_binding(
                binding, f"订单状态 {order.status.value} 不可撤"
            )
            raise TradingException(
                f"订单状态为 {order.status.value}，无法撤销",
                order_id=order_id,
            )

        success = self.adapter.cancel_order(order_id)
        if not success:
            self.approvals.void_order_binding(binding, "撤单失败")
            raise TradingException("撤单失败", order_id=order_id)

        self.approvals.mark_order_committed(binding, order_id)
        order = self.adapter.get_order(order_id)
        self.ledger.record(
            resource_type=ResourceType.ORDER,
            resource_id=order_id,
            executor=principal.actor,
            action="cancel_order",
            decision=decision,
        )
        return self._annotate_order(order_id, order.to_dict())

    def get_order(
        self, order_id: str, principal: Optional[PrincipalContext] = None
    ) -> Dict[str, Any]:
        """业务模块说明。"""
        principal = self._principal(principal)
        order = self.adapter.get_order(order_id)
        if not order:
            raise TradingException("订单不存在", order_id=order_id)
        # 订单读权限按其标的核验（授权资源粒度为标的）
        self.approvals.assert_allowed(
            self._context(principal, Action.READ, ResourceType.ORDER, order.stock_code)
        )
        return self._annotate_order(order_id, order.to_dict())

    def get_orders(
        self,
        stock_code: Optional[str] = None,
        status: Optional[str] = None,
        principal: Optional[PrincipalContext] = None,
    ) -> List[Dict[str, Any]]:
        """业务模块说明。"""
        principal = self._principal(principal)
        # 订单列表只返回此刻对其标的仍有读权限的订单；失权后历史不可见
        order_status = OrderStatus(status) if status else None
        orders = self.adapter.get_orders(stock_code, order_status)
        visible = []
        checked: Dict[str, bool] = {}
        for o in orders:
            if o.stock_code not in checked:
                checked[o.stock_code] = self.approvals.can_read(
                    principal.actor,
                    ResourceType.ORDER,
                    o.stock_code,
                    on_behalf_of=principal.on_behalf_of,
                )
            if checked[o.stock_code]:
                visible.append(self._annotate_order(o.order_id, o.to_dict()))
        return visible

    def get_quote(self, stock_code: str) -> Dict[str, Any]:
        """业务模块说明。"""
        quote = self.adapter.get_quote(stock_code)
        if not quote:
            raise TradingException("无法获取行情数据", stock_code=stock_code)
        return quote

    # ------------------------------------------------------------------
    # 策略（自动交易）
    # ------------------------------------------------------------------
    def execute_signal(
        self,
        stock_code: str,
        signal_type: str,
        signal_strength: float,
        price: float,
        position_ratio: float = 0.1,
        principal: Optional[PrincipalContext] = None,
    ) -> Optional[Dict[str, Any]]:
        """业务模块说明。"""
        principal = self._principal(principal)
        if not self._auto_trade_enabled:
            logger.info(f"Auto trade disabled, signal ignored: {signal_type}")
            return None

        account = self.adapter.get_account()
        if not account:
            return None

        is_buy = signal_type.startswith("BUY")

        if is_buy:
            # 计算买入数量
            available = float(account.available_cash)
            buy_amount = available * position_ratio * signal_strength
            quantity = int(buy_amount / price / 100) * 100  # 100股整数倍

            if quantity >= 100:
                return self.buy(
                    stock_code=stock_code,
                    quantity=quantity,
                    price=price,
                    order_type="limit",
                    signal_type=signal_type,
                    signal_strength=signal_strength,
                    principal=principal,
                )
        else:
            # 卖出
            position = self.adapter.get_position(stock_code)
            if position and position.available_quantity > 0:
                # 根据信号强度决定卖出比例
                sell_quantity = int(position.available_quantity * signal_strength / 100) * 100
                if sell_quantity >= 100:
                    return self.sell(
                        stock_code=stock_code,
                        quantity=sell_quantity,
                        price=price,
                        order_type="limit",
                        signal_type=signal_type,
                        signal_strength=signal_strength,
                        principal=principal,
                    )

        return None

    def enable_auto_trade(
        self, enabled: bool = True, principal: Optional[PrincipalContext] = None
    ) -> None:
        """策略启停属于敏感操作，需策略域执行权限。"""
        principal = self._principal(principal)
        self.approvals.assert_allowed(
            self._context(
                principal, Action.EXECUTE, ResourceType.STRATEGY, "auto-trade"
            )
        )
        self._auto_trade_enabled = enabled
        logger.info(f"Auto trade {'enabled' if enabled else 'disabled'}")

    def check_stop_loss_take_profit(
        self, principal: Optional[PrincipalContext] = None
    ) -> List[Dict[str, Any]]:
        """业务模块说明。"""
        principal = self._principal(principal)
        results = []
        positions = self.adapter.get_positions()

        for pos in positions:
            if self.risk_manager.check_stop_loss(pos):
                # 触发止损
                quote = self.adapter.get_quote(pos.stock_code)
                if quote:
                    try:
                        result = self.sell(
                            stock_code=pos.stock_code,
                            quantity=pos.available_quantity,
                            price=quote["bid_price_1"],
                            order_type="limit",
                            signal_type="STOP_LOSS",
                            principal=principal,
                        )
                        result["trigger"] = "stop_loss"
                        results.append(result)
                    except (TradingException, PermissionDeniedException) as e:
                        logger.error(f"Stop loss failed: {e}")

            elif self.risk_manager.check_take_profit(pos):
                # 触发止盈
                quote = self.adapter.get_quote(pos.stock_code)
                if quote:
                    try:
                        result = self.sell(
                            stock_code=pos.stock_code,
                            quantity=pos.available_quantity,
                            price=quote["bid_price_1"],
                            order_type="limit",
                            signal_type="TAKE_PROFIT",
                            principal=principal,
                        )
                        result["trigger"] = "take_profit"
                        results.append(result)
                    except (TradingException, PermissionDeniedException) as e:
                        logger.error(f"Take profit failed: {e}")

        return results
