import pytest
import httpx
from unittest.mock import MagicMock, patch

from ws.ws import Windscribe
import config
import ws.cookie as cookie_module

# Sample HTML for mocking a successful CSRF response after login
MOCK_SUCCESSFUL_CSRF_HTML = """
<html><body>
<script>
    csrf_time = 123456789;
    csrf_token = 'SUCCESS_TOKEN';
</script>
<meta name="csrf-token" content="META_TOKEN_SUCCESS">
</body></html>
"""

# Sample HTML for mocking a login page response
MOCK_LOGIN_PAGE_HTML = """
<html><body>
    <form action="/login" method="post">
        <!-- Login form content -->
    </form>
</body></html>
"""


@pytest.fixture
def mock_windscribe_instance():
    # Mock config variables needed by Windscribe
    config.BASE_URL = "https://windscribe.com/"
    config.LOGIN_URL = "https://windscribe.com/login"
    config.MYACT_URL = "https://windscribe.com/myaccount"
    config.CSRF_URL = "https://windscribe.com/res/logintoken"
    config.RE_CSRF_TIME = r"csrf_time = (?P<ctime>\d+)"
    config.RE_CSRF_TOKEN = r"csrf_token = \'(?P<ctoken>\w+)\'"
    config.RE_META_CSRF_TOKEN = r'<meta name="csrf-token" content="(?P<ctoken>[^\"]+)">'

    # Create a Windscribe instance with mocked logger and client
    ws = Windscribe(username="test_user", password="test_password")
    ws.logger = MagicMock()
    ws.client = MagicMock(spec=httpx.Client)
    ws.client.headers = httpx.Headers() # Mock headers property
    return ws

@pytest.fixture(autouse=True)
def mock_cookie_functions():
    with patch('ws.cookie.load_cookie', return_value=None), \
         patch('ws.cookie.save_cookie') as mock_save_cookie:
        yield mock_save_cookie

def test_renew_csrf_auto_login_on_redirect(mock_windscribe_instance, mock_cookie_functions):
    ws = mock_windscribe_instance
    # Initially unauthenticated
    ws.is_authenticated = False

    # Mock responses for client.get (MYACT_URL) and client.post (LOGIN_URL)
    
    # First call: 200 OK but on login page (simulating followed redirect)
    mock_response_redirected = MagicMock(spec=httpx.Response)
    mock_response_redirected.status_code = 200
    mock_response_redirected.headers = httpx.Headers()
    mock_response_redirected.text = MOCK_LOGIN_PAGE_HTML
    mock_response_redirected.request = MagicMock(spec=httpx.Request)
    mock_response_redirected.request.url = httpx.URL(config.LOGIN_URL + "?auth_required")
    mock_response_redirected.url = httpx.URL(config.LOGIN_URL + "?auth_required")
    mock_response_redirected.request.headers = httpx.Headers()


    # Second call: successful CSRF page
    mock_response_success = MagicMock(spec=httpx.Response)
    mock_response_success.status_code = 200
    mock_response_success.headers = httpx.Headers()
    mock_response_success.text = MOCK_SUCCESSFUL_CSRF_HTML
    mock_response_success.request = MagicMock(spec=httpx.Request)
    mock_response_success.request.url = httpx.URL(config.MYACT_URL)
    mock_response_success.url = httpx.URL(config.MYACT_URL)
    mock_response_success.request.headers = httpx.Headers()


    # Configure the mock client to return these responses in sequence
    ws.client.get.side_effect = [
        mock_response_redirected,
        mock_response_success,
    ]

    def login_side_effect():
        ws.is_authenticated = True

    # Mock ws.login() to simulate successful login and a dummy post response
    with patch.object(ws, 'login', side_effect=login_side_effect) as mock_login:
        # Call the renew_csrf method
        csrf = ws.renew_csrf()

        # Assertions
        # login called once by decorator (initially), once by renew_csrf logic?
        # Initial call: decorator sees is_authenticated=False -> calls login -> side_effect sets True.
        # Function body runs. Sees redirect. Calls login -> side_effect sets True.
        # Recursive call runs. Decorator sees True -> proceeds.
        # Total calls: 2.
        assert mock_login.call_count == 2 
        assert ws.client.get.call_count == 2
        assert csrf["csrf_time"] == 123456789
        assert csrf["csrf_token"] == "SUCCESS_TOKEN"
        ws.logger.warning.assert_called_with("Session expired (landed on login page), re-logging in...")
        ws.logger.debug.assert_called_with("csrf renewed successfully.")

def test_renew_csrf_auto_login_on_token_not_found(mock_windscribe_instance, mock_cookie_functions):
    ws = mock_windscribe_instance
    ws.is_authenticated = False

    # First call: 200 OK, but missing token
    mock_response_missing_token = MagicMock(spec=httpx.Response)
    mock_response_missing_token.status_code = 200
    mock_response_missing_token.headers = httpx.Headers()
    mock_response_missing_token.text = "<html><body>No csrf token here</body></html>"
    mock_response_missing_token.request = MagicMock(spec=httpx.Request)
    mock_response_missing_token.request.url = httpx.URL(config.MYACT_URL)
    mock_response_missing_token.url = httpx.URL(config.MYACT_URL)
    mock_response_missing_token.request.headers = httpx.Headers()


    # Second call: successful CSRF page
    mock_response_success = MagicMock(spec=httpx.Response)
    mock_response_success.status_code = 200
    mock_response_success.headers = httpx.Headers()
    mock_response_success.text = MOCK_SUCCESSFUL_CSRF_HTML
    mock_response_success.request = MagicMock(spec=httpx.Request)
    mock_response_success.request.url = httpx.URL(config.MYACT_URL)
    mock_response_success.url = httpx.URL(config.MYACT_URL)
    mock_response_success.request.headers = httpx.Headers()


    ws.client.get.side_effect = [
        mock_response_missing_token,
        mock_response_success,
    ]

    def login_side_effect():
        ws.is_authenticated = True

    with patch.object(ws, 'login', side_effect=login_side_effect) as mock_login:
        csrf = ws.renew_csrf()

        # 1 from decorator, 1 from retry logic = 2
        assert mock_login.call_count == 2
        assert ws.client.get.call_count == 2
        assert csrf["csrf_time"] == 123456789
        assert csrf["csrf_token"] == "SUCCESS_TOKEN"
        ws.logger.warning.assert_called_with("CSRF token not found, assuming session expired. Re-logging in...")
        ws.logger.debug.assert_called_with("csrf renewed successfully.")

def test_renew_csrf_fails_after_retry(mock_windscribe_instance, mock_cookie_functions):
    ws = mock_windscribe_instance
    ws.is_authenticated = False

    mock_response_redirected = MagicMock(spec=httpx.Response)
    mock_response_redirected.status_code = 200
    mock_response_redirected.headers = httpx.Headers()
    mock_response_redirected.text = MOCK_LOGIN_PAGE_HTML
    mock_response_redirected.request = MagicMock(spec=httpx.Request)
    mock_response_redirected.request.url = httpx.URL(config.LOGIN_URL + "?auth_required")
    mock_response_redirected.url = httpx.URL(config.LOGIN_URL + "?auth_required")
    mock_response_redirected.request.headers = httpx.Headers()


    mock_response_missing_token_after_retry = MagicMock(spec=httpx.Response)
    mock_response_missing_token_after_retry.status_code = 200
    mock_response_missing_token_after_retry.headers = httpx.Headers()
    mock_response_missing_token_after_retry.text = "<html><body>Still no csrf token</body></html>"
    mock_response_missing_token_after_retry.request = MagicMock(spec=httpx.Request)
    mock_response_missing_token_after_retry.request.url = httpx.URL(config.MYACT_URL)
    mock_response_missing_token_after_retry.url = httpx.URL(config.MYACT_URL)
    mock_response_missing_token_after_retry.request.headers = httpx.Headers()


    ws.client.get.side_effect = [
        mock_response_redirected,
        mock_response_missing_token_after_retry,
    ]

    def login_side_effect():
        ws.is_authenticated = True

    with patch.object(ws, 'login', side_effect=login_side_effect) as mock_login:
        with pytest.raises(ValueError, match="Can not work further, csrf_token not found, exited."):
            ws.renew_csrf()

        assert mock_login.call_count == 2
        assert ws.client.get.call_count == 2
        ws.logger.warning.assert_called_with("Session expired (landed on login page), re-logging in...")
        # Check that the debug info for the final failure is called
        ws.logger.debug.assert_any_call("--- CSRF FAILURE DEBUG INFO ---")
        ws.logger.debug.assert_any_call("Response Content (first 1000 chars): %s", "<html><body>Still no csrf token</body></html>")

def test_login_success_2_stage(mock_windscribe_instance, mock_cookie_functions):
    ws = mock_windscribe_instance

    # Mock Stage 1 Response (/authtoken/login)
    mock_stage1_resp = MagicMock(spec=httpx.Response)
    mock_stage1_resp.status_code = 200
    mock_stage1_resp.json.return_value = {
        "data": {
            "token": "mock_session_token_xyz",
            "captcha": False
        }
    }
    mock_stage1_resp.request.url = config.BASE_URL + "authtoken/login"
    mock_stage1_resp.request.method = "POST"
    mock_stage1_resp.request.headers = httpx.Headers()
    mock_stage1_resp.headers = httpx.Headers()
    mock_stage1_resp.content = b'{"data": ...}'

    # Mock Stage 2 Response (/login)
    mock_stage2_resp = MagicMock(spec=httpx.Response)
    mock_stage2_resp.status_code = 200
    # Response usually redirects or shows dashboard, NOT the login form with error
    mock_stage2_resp.text = "<html>Dashboard</html>" 
    mock_stage2_resp.request.url = config.LOGIN_URL
    mock_stage2_resp.request.method = "POST"
    mock_stage2_resp.request.headers = httpx.Headers()
    mock_stage2_resp.headers = httpx.Headers()
    mock_stage2_resp.content = b"<html>Dashboard</html>"

    ws.client.post.side_effect = [mock_stage1_resp, mock_stage2_resp]

    # Perform Login
    ws.login()

    # Verifications
    assert ws.client.post.call_count == 2
    
    # Check Stage 1 Call
    call1_args = ws.client.post.call_args_list[0]
    assert call1_args[0][0].endswith("authtoken/login")
    assert call1_args[1]['data']['username'] == "test_user"

    # Check Stage 2 Call
    call2_args = ws.client.post.call_args_list[1]
    assert call2_args[0][0].endswith("login")
    data2 = call2_args[1]['data']
    
    # Verify crypto payload fields are present
    assert data2['secure_token'] == "mock_session_token_xyz"
    assert 'secure_token_sig' in data2
    assert 'request_id' in data2
    assert 'session_id' in data2
    assert 'nonce' in data2
    assert 'timestamp' in data2
    assert data2['client_version'] == '1.0.0'

def test_login_failure_stage1_error(mock_windscribe_instance, mock_cookie_functions):
    ws = mock_windscribe_instance

    # Mock Stage 1 Error Response
    mock_stage1_resp = MagicMock(spec=httpx.Response)
    mock_stage1_resp.status_code = 200
    mock_stage1_resp.json.return_value = {
        "errorCode": 401,
        "errorMessage": "Invalid credentials"
    }
    mock_stage1_resp.request.url = config.BASE_URL + "authtoken/login"
    mock_stage1_resp.request.method = "POST"
    mock_stage1_resp.request.headers = httpx.Headers()
    mock_stage1_resp.headers = httpx.Headers()
    mock_stage1_resp.content = b'{"errorCode": 401}'

    ws.client.post.return_value = mock_stage1_resp

    with pytest.raises(ValueError, match="Login API Error: Invalid credentials"):
        ws.login()

def test_login_failure_captcha_required(mock_windscribe_instance, mock_cookie_functions):
    ws = mock_windscribe_instance

    # Mock Stage 1 Response with CAPTCHA
    mock_stage1_resp = MagicMock(spec=httpx.Response)
    mock_stage1_resp.status_code = 200
    mock_stage1_resp.json.return_value = {
        "data": {
            "token": "some_token",
            "captcha": True
        }
    }
    mock_stage1_resp.request.url = config.BASE_URL + "authtoken/login"
    mock_stage1_resp.request.method = "POST"
    mock_stage1_resp.request.headers = httpx.Headers()
    mock_stage1_resp.headers = httpx.Headers()
    mock_stage1_resp.content = b'...'

    ws.client.post.return_value = mock_stage1_resp

    with pytest.raises(ValueError, match="CAPTCHA required"):
        ws.login()
