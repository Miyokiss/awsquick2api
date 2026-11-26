"""Bounded diagnostics for untrusted upstream failure metadata."""

import re


_ERROR_CODES = frozenset({
    'FrameTooLarge', 'context_overflow', 'bad_request', 'conversation_format', 'INVALID_REQUEST',
    'content_filtered', 'guardrail_blocked', 'turn_aborted', 'ThrottlingException', 'rate_limited',
    'service_error', 'IDLE_TIMEOUT', 'InternalServerException', 'ServiceUnavailableException',
    'ValidationException', 'AccessDeniedException', 'ResourceNotFoundException',
    'UnauthorizedException', 'ConflictException', 'RequestTimeout', 'ModelTimeoutException',
    'ModelErrorException', 'ServiceQuotaExceededException',
    'error_event', 'error_frame', 'protocol_error', 'network_error', 'websocket_closed',
    'upstream_timeout', 'invalid_upstream_output',
})


def safe_upstream_code(value: object) -> str:
    if isinstance(value, str) and (
        value in _ERROR_CODES or re.fullmatch(r'HTTP_[1-5][0-9]{2}', value)
    ):
        return value
    return ''
