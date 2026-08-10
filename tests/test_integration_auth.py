import base64

import httpx
import respx

from app.integration.auth import AuthStrategy, BasicAuthStrategy, JWTBearerAuthStrategy

MANAGER_URL = "https://wazuh-manager.test:55000"


def test_basic_auth_strategy_satisfies_auth_strategy_protocol():
    assert isinstance(BasicAuthStrategy("u", "p"), AuthStrategy)


def test_jwt_bearer_strategy_satisfies_auth_strategy_protocol():
    assert isinstance(JWTBearerAuthStrategy(httpx.Client(), "u", "p"), AuthStrategy)


def test_basic_auth_strategy_encodes_credentials():
    strategy = BasicAuthStrategy(username="admin", password="secret-pw")
    headers = strategy.get_headers()
    expected = base64.b64encode(b"admin:secret-pw").decode()
    assert headers == {"Authorization": f"Basic {expected}"}


def test_basic_auth_strategy_refresh_is_a_noop():
    strategy = BasicAuthStrategy(username="admin", password="secret-pw")
    strategy.refresh()  # must not raise


@respx.mock
def test_jwt_strategy_authenticates_on_first_use():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    client = httpx.Client(base_url=MANAGER_URL)
    strategy = JWTBearerAuthStrategy(client=client, username="wazuh-wui", password="test-pw")

    headers = strategy.get_headers()

    assert headers == {"Authorization": "Bearer abc123"}


@respx.mock
def test_jwt_strategy_caches_token_across_calls():
    route = respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    client = httpx.Client(base_url=MANAGER_URL)
    strategy = JWTBearerAuthStrategy(client=client, username="wazuh-wui", password="test-pw")

    strategy.get_headers()
    strategy.get_headers()

    assert route.call_count == 1


@respx.mock
def test_jwt_strategy_refresh_re_authenticates():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        side_effect=[
            httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0}),
            httpx.Response(200, json={"data": {"token": "def456"}, "error": 0}),
        ]
    )
    client = httpx.Client(base_url=MANAGER_URL)
    strategy = JWTBearerAuthStrategy(client=client, username="wazuh-wui", password="test-pw")

    strategy.get_headers()
    strategy.refresh()
    headers = strategy.get_headers()

    assert headers == {"Authorization": "Bearer def456"}
