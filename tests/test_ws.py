import pytest
import httpx
from unittest.mock import MagicMock, patch

from src.ws.ws import Windscribe
import src.config as config
import src.ws.cookie as cookie_module

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
    with patch('src.ws.cookie.load_cookie', return_value=None), \
         patch('src.ws.cookie.save_cookie') as mock_save_cookie:
        yield mock_save_cookie

def test_renew_csrf_auto_login_on_redirect(mock_windscribe_instance, mock_cookie_functions):
    ws = mock_windscribe_instance

    # Mock responses for client.get (MYACT_URL) and client.post (LOGIN_URL)
    # Scenario:
    # 1. Initial call to MYACT_URL gets 302 redirect to login.
    # 2. ws.login() is called.
    # 3. Second call to MYACT_URL (after login) gets successful CSRF HTML.

    # Mock the sequence of responses from httpx.Client.get
    # First call: 302 redirect
    mock_response_302 = MagicMock(spec=httpx.Response)
    mock_response_302.status_code = 302
    mock_response_302.headers = httpx.Headers({'Location': config.LOGIN_URL})
    mock_response_302.text = MOCK_LOGIN_PAGE_HTML
    mock_response_302.request = MagicMock(spec=httpx.Request)
    mock_response_302.request.url = config.MYACT_URL
    mock_response_302.request.headers = httpx.Headers()


    # Second call: successful CSRF page
    mock_response_success = MagicMock(spec=httpx.Response)
    mock_response_success.status_code = 200
    mock_response_success.headers = httpx.Headers()
    mock_response_success.text = MOCK_SUCCESSFUL_CSRF_HTML
    mock_response_success.request = MagicMock(spec=httpx.Request)
    mock_response_success.request.url = config.MYACT_URL
    mock_response_success.request.headers = httpx.Headers()


    # Configure the mock client to return these responses in sequence
    ws.client.get.side_effect = [
        mock_response_302,
        mock_response_success,
    ]

    # Mock ws.login() to simulate successful login and a dummy post response
    with patch.object(ws, 'login') as mock_login:
        # Mock the post request that login() makes
        mock_login_post_response = MagicMock(spec=httpx.Response)
        mock_login_post_response.status_code = 200
        mock_login_post_response.text = "Login successful"
        ws.client.post.return_value = mock_login_post_response

        # Call the renew_csrf method
        csrf = ws.renew_csrf()

        # Assertions
        mock_login.assert_called_once() # login() should be called once
        assert ws.client.get.call_count == 2 # MYACT_URL should be requested twice
        assert csrf["csrf_time"] == 123456789
        assert csrf["csrf_token"] == "SUCCESS_TOKEN"
        ws.logger.warning.assert_called_with("Session expired (redirect detected), re-logging in...")
        ws.logger.debug.assert_called_with("csrf renewed successfully.")

def test_renew_csrf_auto_login_on_token_not_found(mock_windscribe_instance, mock_cookie_functions):
    ws = mock_windscribe_instance

    # Scenario:
    # 1. Initial call to MYACT_URL gets 200 but no token in content.
    # 2. ws.login() is called.
    # 3. Second call to MYACT_URL (after login) gets successful CSRF HTML.

    # First call: 200 OK, but missing token
    mock_response_missing_token = MagicMock(spec=httpx.Response)
    mock_response_missing_token.status_code = 200
    mock_response_missing_token.headers = httpx.Headers()
    mock_response_missing_token.text = "<html><body>No csrf token here</body></html>"
    mock_response_missing_token.request = MagicMock(spec=httpx.Request)
    mock_response_missing_token.request.url = config.MYACT_URL
    mock_response_missing_token.request.headers = httpx.Headers()


    # Second call: successful CSRF page
    mock_response_success = MagicMock(spec=httpx.Response)
    mock_response_success.status_code = 200
    mock_response_success.headers = httpx.Headers()
    mock_response_success.text = MOCK_SUCCESSFUL_CSRF_HTML
    mock_response_success.request = MagicMock(spec=httpx.Request)
    mock_response_success.request.url = config.MYACT_URL
    mock_response_success.request.headers = httpx.Headers()


    ws.client.get.side_effect = [
        mock_response_missing_token,
        mock_response_success,
    ]

    with patch.object(ws, 'login') as mock_login:
        mock_login_post_response = MagicMock(spec=httpx.Response)
        mock_login_post_response.status_code = 200
        mock_login_post_response.text = "Login successful"
        ws.client.post.return_value = mock_login_post_response

        csrf = ws.renew_csrf()

        mock_login.assert_called_once()
        assert ws.client.get.call_count == 2
        assert csrf["csrf_time"] == 123456789
        assert csrf["csrf_token"] == "SUCCESS_TOKEN"
        ws.logger.warning.assert_called_with("CSRF token not found, assuming session expired. Re-logging in...")
        ws.logger.debug.assert_called_with("csrf renewed successfully.")

def test_renew_csrf_fails_after_retry(mock_windscribe_instance, mock_cookie_functions):
    ws = mock_windscribe_instance

    # Scenario:
    # 1. Initial call: 302 redirect
    # 2. ws.login() is called.
    # 3. Second call: 200 but still no token. Should raise ValueError.

    mock_response_302 = MagicMock(spec=httpx.Response)
    mock_response_302.status_code = 302
    mock_response_302.headers = httpx.Headers({'Location': config.LOGIN_URL})
    mock_response_302.text = MOCK_LOGIN_PAGE_HTML
    mock_response_302.request = MagicMock(spec=httpx.Request)
    mock_response_302.request.url = config.MYACT_URL
    mock_response_302.request.headers = httpx.Headers()


    mock_response_missing_token_after_retry = MagicMock(spec=httpx.Response)
    mock_response_missing_token_after_retry.status_code = 200
    mock_response_missing_token_after_retry.headers = httpx.Headers()
    mock_response_missing_token_after_retry.text = "<html><body>Still no csrf token</body></html>"
    mock_response_missing_token_after_retry.request = MagicMock(spec=httpx.Request)
    mock_response_missing_token_after_retry.request.url = config.MYACT_URL
    mock_response_missing_token_after_retry.request.headers = httpx.Headers()


    ws.client.get.side_effect = [
        mock_response_302,
        mock_response_missing_token_after_retry,
    ]

    with patch.object(ws, 'login') as mock_login:
        mock_login_post_response = MagicMock(spec=httpx.Response)
        mock_login_post_response.status_code = 200
        mock_login_post_response.text = "Login successful"
        ws.client.post.return_value = mock_login_post_response

        with pytest.raises(ValueError, match="Can not work further, csrf_token not found, exited."):
            ws.renew_csrf()

        mock_login.assert_called_once()
        assert ws.client.get.call_count == 2
        ws.logger.warning.assert_called_with("Session expired (redirect detected), re-logging in...")
        # Check that the debug info for the final failure is called
        ws.logger.debug.assert_any_call("--- CSRF FAILURE DEBUG INFO ---")
        ws.logger.debug.assert_any_call("Response Content (first 1000 chars): %s", "<html><body>Still no csrf token</body></html>")
