import pytest

from app import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_weak_password_detection(client):
    response = client.post("/check", json={"password": "12345"})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["label"] == "WEAK"
    assert payload["score"] <= 1


def test_common_password_blocklist_hit(client):
    response = client.post("/check", json={"password": "password"})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["commonPassword"] is True


def test_rockyou_password_hit(client):
    response = client.post("/check", json={"password": "password123"})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["commonPassword"] is True
    assert payload["commonPasswordSource"] == "rockyou"


def test_rejects_oversized_input(client):
    response = client.post("/check", json={"password": "a" * 129})
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "bad_request"

    big_password = "a" * 2050
    response = client.post("/check", json={"password": big_password})
    assert response.status_code == 413
    payload = response.get_json()
    assert payload["error"] == "payload_too_large"


def test_check_wrong_method_returns_json(client):
    response = client.get("/check")
    assert response.status_code == 405
    payload = response.get_json()
    assert payload["error"] == "method_not_allowed"


def test_check_wrong_content_type(client):
    response = client.post("/check", data="password=bad")
    assert response.status_code == 415
    payload = response.get_json()
    assert payload["error"] == "unsupported_media_type"


def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    payload = response.get_json()
    assert set(payload.keys()) == {"status", "version", "hibp_enabled"}


def test_not_found_json(client):
    response = client.get("/no_such_route")
    assert response.status_code == 404
    payload = response.get_json()
    assert payload["error"] == "not_found"


def test_rate_limited(client):
    response = None
    for _ in range(11):
        response = client.post("/check", json={"password": "Weakpass123!"})
    assert response is not None
    assert response.status_code == 429
    payload = response.get_json()
    assert payload["error"] == "rate_limited"
