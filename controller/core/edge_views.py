from functools import wraps
from uuid import uuid4

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .enrollment import (
    GRANT_AUTH_SCHEME,
    EdgeAPIError,
    accept_heartbeat,
    claim_enrollment,
    create_enrollment_challenge,
    create_node_challenge,
    get_enrollment_status,
    parse_json_bytes,
)


def _json_response(payload, *, status=200):
    response = JsonResponse(payload, status=status)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return response


def _edge_endpoint(view):
    @csrf_exempt
    @wraps(view)
    def wrapped(request):
        if request.method != "POST":
            response = _json_response(
                {
                    "apiVersion": "edge.vivolution.ae/error/v1",
                    "code": "method_not_allowed",
                    "message": "Only POST is allowed.",
                    "requestId": str(uuid4()),
                },
                status=405,
            )
            response.headers["Allow"] = "POST"
            return response
        if not settings.TESTING and not request.is_secure():
            return _json_response(
                {
                    "apiVersion": "edge.vivolution.ae/error/v1",
                    "code": "https_required",
                    "message": "HTTPS is required.",
                    "requestId": str(uuid4()),
                },
                status=400,
            )
        content_type = request.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            return _json_response(
                {
                    "apiVersion": "edge.vivolution.ae/error/v1",
                    "code": "unsupported_media_type",
                    "message": "Content-Type must be application/json.",
                    "requestId": str(uuid4()),
                },
                status=415,
            )
        content_length = request.META.get("CONTENT_LENGTH")
        try:
            parsed_content_length = int(content_length) if content_length else 0
        except ValueError:
            return _json_response(
                {
                    "apiVersion": "edge.vivolution.ae/error/v1",
                    "code": "invalid_content_length",
                    "message": "Content-Length is invalid.",
                    "requestId": str(uuid4()),
                },
                status=400,
            )
        if parsed_content_length < 0:
            return _json_response(
                {
                    "apiVersion": "edge.vivolution.ae/error/v1",
                    "code": "invalid_content_length",
                    "message": "Content-Length is invalid.",
                    "requestId": str(uuid4()),
                },
                status=400,
            )
        try:
            if parsed_content_length > settings.EDGE_API_MAX_BODY_BYTES:
                raise EdgeAPIError(413, "body_too_large", "Request body is too large.")
            raw_body = request.body
            payload = parse_json_bytes(raw_body)
            result, status = view(request, payload, raw_body)
        except RequestDataTooBig:
            return _json_response(
                {
                    "apiVersion": "edge.vivolution.ae/error/v1",
                    "code": "body_too_large",
                    "message": "Request body is too large.",
                    "requestId": str(uuid4()),
                },
                status=413,
            )
        except EdgeAPIError as exc:
            return _json_response(
                {
                    "apiVersion": "edge.vivolution.ae/error/v1",
                    "code": exc.code,
                    "message": exc.message,
                    "requestId": str(uuid4()),
                },
                status=exc.status,
            )
        return _json_response(result, status=status)

    return wrapped


def _grant_token(request):
    authorization = request.headers.get("Authorization", "")
    prefix = f"{GRANT_AUTH_SCHEME} "
    if not authorization.startswith(prefix) or authorization.count(" ") != 1:
        raise EdgeAPIError(401, "invalid_grant", "Enrollment grant is invalid.")
    token = authorization[len(prefix) :]
    if not token or len(token) > 128:
        raise EdgeAPIError(401, "invalid_grant", "Enrollment grant is invalid.")
    return token


@_edge_endpoint
def enrollment_challenge(request, payload, _raw_body):
    result = create_enrollment_challenge(
        grant_token=_grant_token(request),
        request_data=payload,
    )
    return result, 201


@_edge_endpoint
def enrollment_claim(request, payload, raw_body):
    return claim_enrollment(
        grant_token=_grant_token(request),
        envelope=payload,
        raw_body=raw_body,
    )


@_edge_endpoint
def node_challenge(_request, payload, _raw_body):
    return create_node_challenge(request_data=payload), 201


@_edge_endpoint
def enrollment_status(_request, payload, raw_body):
    return get_enrollment_status(envelope=payload, raw_body=raw_body), 200


@_edge_endpoint
def node_heartbeat(_request, payload, raw_body):
    return accept_heartbeat(envelope=payload, raw_body=raw_body), 200
