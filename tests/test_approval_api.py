"""审批权限接口的端到端测试。

通过 HTTP 头 X-Operator-Id / X-Approver-Id / X-Idempotency-Key 驱动
申请、批准、下单、撤回、过期与读过滤的完整链路。
"""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import init_database
from app.security.context import reset_registry


def iso(dt: datetime) -> str:
    return dt.isoformat()


@pytest.fixture
def client():
    """业务模块说明。"""
    init_database()
    reset_registry()
    with TestClient(app) as c:
        # 每个用例重连，重置模拟账户与订单
        c.post("/api/trading/connect", json={"adapter_type": "simulation", "config": {"initial_cash": 1000000}})
        yield c


def _order_grant(client: TestClient, subject="trader1", approver="boss", hours=2):
    now = datetime.utcnow()
    resp = client.post(
        "/api/approvals/requests",
        json={
            "requester": "agent1",
            "subject": subject,
            "resource_type": "order",
            "resource_id": "000001",
            "actions": ["read", "place_order", "cancel_order"],
            "valid_from": iso(now - timedelta(hours=1)),
            "valid_until": iso(now + timedelta(hours=hours)),
        },
    )
    assert resp.status_code == 200, resp.text
    request_id = resp.json()["request_id"]
    resp = client.post(
        f"/api/approvals/requests/{request_id}/approve",
        json={},
        headers={"X-Approver-Id": approver},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestBootstrapCompatibility:
    def test_legacy_calls_without_identity_still_work(self, client):
        resp = client.post(
            "/api/trading/buy",
            json={"stock_code": "000001", "quantity": 100, "price": 10.0},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "filled"


class TestApprovalTradingFlow:
    def test_unapproved_user_forbidden(self, client):
        resp = client.post(
            "/api/trading/buy",
            json={"stock_code": "000001", "quantity": 100, "price": 10.0},
            headers={"X-Operator-Id": "newbie"},
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "PERMISSION_DENIED"

    def test_pending_request_returns_pending_403(self, client):
        now = datetime.utcnow()
        client.post(
            "/api/approvals/requests",
            json={
                "requester": "agent1",
                "subject": "trader1",
                "resource_type": "order",
                "resource_id": "000001",
                "actions": ["place_order"],
                "valid_from": iso(now - timedelta(hours=1)),
                "valid_until": iso(now + timedelta(hours=2)),
            },
        )
        resp = client.post(
            "/api/trading/buy",
            json={"stock_code": "000001", "quantity": 100, "price": 10.0},
            headers={"X-Operator-Id": "trader1"},
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "APPROVAL_PENDING"

    def test_approved_user_trades_and_order_keeps_approver(self, client):
        _order_grant(client)
        resp = client.post(
            "/api/trading/buy",
            json={"stock_code": "000001", "quantity": 100, "price": 10.0},
            headers={"X-Operator-Id": "trader1"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["executor"] == "trader1"
        assert data["approver"] == "boss"

        # 历史查询保留执行人/批准人
        resp = client.get(
            "/api/trading/orders", headers={"X-Operator-Id": "trader1"}
        )
        orders = resp.json()["orders"]
        assert len(orders) == 1
        assert orders[0]["executor"] == "trader1"
        assert orders[0]["approver"] == "boss"

    def test_self_approval_rejected(self, client):
        now = datetime.utcnow()
        resp = client.post(
            "/api/approvals/requests",
            json={
                "requester": "trader1",
                "subject": "trader1",
                "resource_type": "order",
                "resource_id": "000001",
                "actions": ["place_order"],
                "valid_from": iso(now - timedelta(hours=1)),
                "valid_until": iso(now + timedelta(hours=2)),
            },
        )
        request_id = resp.json()["request_id"]
        resp = client.post(
            f"/api/approvals/requests/{request_id}/approve",
            json={},
            headers={"X-Approver-Id": "trader1"},
        )
        assert resp.status_code == 403


class TestRevokeAndReadFilter:
    def test_revoke_blocks_trade_and_history(self, client):
        grant = _order_grant(client)
        headers = {"X-Operator-Id": "trader1"}
        client.post(
            "/api/trading/buy",
            json={"stock_code": "000001", "quantity": 100, "price": 10.0},
            headers=headers,
        )
        # 撤回授权
        resp = client.post(
            f"/api/approvals/grants/{grant['grant_id']}/revoke",
            json={"reason": "临时授权结束"},
            headers={"X-Approver-Id": "boss"},
        )
        assert resp.status_code == 200

        # 不能继续下单
        resp = client.post(
            "/api/trading/buy",
            json={"stock_code": "000001", "quantity": 100, "price": 10.0},
            headers=headers,
        )
        assert resp.status_code == 403

        # 历史订单不再可读
        assert client.get("/api/trading/orders", headers=headers).json()["orders"] == []

    def test_non_approver_cannot_revoke(self, client):
        grant = _order_grant(client)
        resp = client.post(
            f"/api/approvals/grants/{grant['grant_id']}/revoke",
            json={"reason": "x"},
            headers={"X-Approver-Id": "intruder"},
        )
        assert resp.status_code == 403


class TestConflictFlow:
    def test_conflict_then_override(self, client):
        first = _order_grant(client)
        now = datetime.utcnow()
        resp = client.post(
            "/api/approvals/requests",
            json={
                "requester": "agent2",
                "subject": "trader1",
                "resource_type": "order",
                "resource_id": "000001",
                "actions": ["place_order"],
                "valid_from": iso(now),
                "valid_until": iso(now + timedelta(hours=3)),
            },
        )
        request_id = resp.json()["request_id"]
        resp = client.post(
            f"/api/approvals/requests/{request_id}/approve",
            json={},
            headers={"X-Approver-Id": "boss"},
        )
        assert resp.status_code == 409

        resp = client.post(
            f"/api/approvals/requests/{request_id}/resolve-conflict",
            json={"approve_with_override": True},
            headers={"X-Approver-Id": "boss"},
        )
        assert resp.status_code == 200
        # 旧授权被取代
        grants = client.get(
            "/api/approvals/grants",
            params={"subject": "trader1", "resource_type": "order"},
            headers={"X-Approver-Id": "boss"},
        ).json()["grants"]
        statuses = {g["grant_id"]: g["status"] for g in grants}
        assert statuses[first["grant_id"]] == "superseded"


class TestIdempotency:
    def test_duplicate_request_places_once(self, client):
        _order_grant(client)
        headers = {"X-Operator-Id": "trader1", "X-Idempotency-Key": "fixed-key"}
        payload = {"stock_code": "000001", "quantity": 100, "price": 10.0}
        r1 = client.post("/api/trading/buy", json=payload, headers=headers)
        r2 = client.post("/api/trading/buy", json=payload, headers=headers)
        assert r1.json()["order_id"] == r2.json()["order_id"]
        orders = client.get(
            "/api/trading/orders", headers={"X-Operator-Id": "trader1"}
        ).json()["orders"]
        assert len(orders) == 1


class TestExpiry:
    def test_sweep_expires_past_window_grant(self, client):
        now = datetime.utcnow()
        # 造一条窗口已结束的授权
        resp = client.post(
            "/api/approvals/requests",
            json={
                "requester": "agent1",
                "subject": "trader1",
                "resource_type": "order",
                "resource_id": "000001",
                "actions": ["place_order", "read"],
                "valid_from": iso(now - timedelta(hours=2)),
                "valid_until": iso(now - timedelta(hours=1)),
            },
        )
        request_id = resp.json()["request_id"]
        grant = client.post(
            f"/api/approvals/requests/{request_id}/approve",
            json={},
            headers={"X-Approver-Id": "boss"},
        ).json()
        assert grant["status"] == "active"

        # 清理后授权过期
        sweep = client.post(
            "/api/approvals/expire-sweep", headers={"X-Approver-Id": "boss"}
        ).json()
        assert sweep["expired_grants"] == 1

        # 过期授权无法下单
        resp = client.post(
            "/api/trading/buy",
            json={"stock_code": "000001", "quantity": 100, "price": 10.0},
            headers={"X-Operator-Id": "trader1"},
        )
        assert resp.status_code == 403


class TestAudit:
    def test_audit_requires_approver_header(self, client):
        resp = client.get("/api/approvals/audit")
        assert resp.status_code == 403

    def test_audit_records_lifecycle(self, client):
        _order_grant(client)
        resp = client.get(
            "/api/approvals/audit", headers={"X-Approver-Id": "auditor"}
        )
        assert resp.status_code == 200
        types = {e["event_type"] for e in resp.json()["events"]}
        assert "request_submitted" in types
        assert "request_approved" in types

    def test_decisions_listed(self, client):
        _order_grant(client)
        client.post(
            "/api/trading/buy",
            json={"stock_code": "000001", "quantity": 100, "price": 10.0},
            headers={"X-Operator-Id": "trader1"},
        )
        resp = client.get(
            "/api/approvals/decisions",
            params={"actor": "trader1"},
            headers={"X-Approver-Id": "boss"},
        )
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1
