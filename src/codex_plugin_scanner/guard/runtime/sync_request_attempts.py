"""HTTP attempt and retry steps behind the existing runtime facade."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable


def _urlopen_with_sync_retries(
    *,
    request: urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
    parse_json_response: bool,
    nonce_fast_path: bool,
    validate_request: Callable[[], None] | None = None,
    prepare_request: Callable[[urllib.request.Request], None] | None = None,
) -> object:
    """Drive one Guard Cloud request through the shared sync retry policies.

    Retry order is deliberate: an optional DPoP nonce fast path for raw
    requests, then bounded 429 rate-limit waits with a freshly signed
    request, then bounded gateway retries, then the generic DPoP nonce
    challenge retry, and finally one timeout retry at the longer budget.
    """

    from . import runner as api

    def error_payload(error: urllib.error.HTTPError) -> object:
        payload = api._http_error_payload(error)
        if validate_request is not None:
            validate_request()
        return payload

    current_request = request
    current_timeout_seconds = timeout_seconds
    retried_timeout = False
    nonce_retry_count = 0
    rate_limit_retry_count = 0
    gateway_retry_count = 0
    while True:
        if prepare_request is not None:
            prepare_request(current_request)
        # The validator is outside the transport try/except: a failed local
        # authority check must never be mistaken for a retryable network error.
        if validate_request is not None:
            validate_request()
        try:
            with api.managed_urlopen(current_request, timeout=current_timeout_seconds) as response:
                payload = api.json.loads(response.read().decode("utf-8")) if parse_json_response else None
        except api.urllib.error.HTTPError as error:
            if validate_request is not None:
                validate_request()
            if nonce_fast_path and error.code == 401:
                parsed_error = error_payload(error)
                dpop_nonce = api._dpop_nonce_from_http_error(error, parsed_error)
                if dpop_nonce is not None and nonce_retry_count < 3:
                    nonce_retry_count += 1
                    retry_request = api._guard_sync_request_with_nonce(current_request, dpop_nonce)
                    if retry_request is not None:
                        current_request = retry_request
                        current_timeout_seconds = timeout_seconds
                        retried_timeout = False
                        continue
            if error.code == 429 and rate_limit_retry_count < 2:
                retry_after = api._parse_retry_after_header(error)
                api.time.sleep(min(retry_after, 120))
                rate_limit_retry_count += 1
                refreshed_request = api._refresh_guard_sync_request(current_request)
                if refreshed_request is None:
                    raise
                current_request = refreshed_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            if (
                api._retryable_gateway_http_error(error)
                and gateway_retry_count < api._SYNC_RETRYABLE_GATEWAY_MAX_ATTEMPTS
            ):
                retry_after = api._retry_after_sleep_seconds(error, retry_timeout_seconds)
                api.time.sleep(retry_after)
                gateway_retry_count += 1
                current_request = api._request_for_gateway_retry(current_request)
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            parsed_error = error_payload(error) if error.code in {400, 401} else None
            dpop_nonce = api._dpop_nonce_from_http_error(error, parsed_error)
            retry_request = (
                None
                if dpop_nonce is None or nonce_retry_count >= 3
                else api._guard_sync_request_with_nonce(current_request, dpop_nonce)
            )
            if retry_request is not None:
                nonce_retry_count += 1
                current_request = retry_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            raise
        except OSError as error:
            if validate_request is not None:
                validate_request()
            if not retried_timeout and api._is_timeout_error(error):
                refreshed_request = api._refresh_guard_sync_request(current_request)
                if refreshed_request is None:
                    raise
                current_request = refreshed_request
                current_timeout_seconds = retry_timeout_seconds
                retried_timeout = True
                continue
            raise
        except Exception:
            # Parsing and response cleanup also complete a transport attempt.
            if validate_request is not None:
                validate_request()
            raise
        if validate_request is not None:
            validate_request()
        return payload
