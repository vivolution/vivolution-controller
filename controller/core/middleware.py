from django.db import connection, transaction

from .rls import set_local_rls_context


class OperatorRLSMiddleware:
    """Give authenticated staff an explicit, transaction-local RLS operator context."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        is_operator = bool(user and user.is_authenticated and user.is_staff)
        if not is_operator or connection.vendor != "postgresql":
            return self.get_response(request)

        with transaction.atomic():
            set_local_rls_context(operator=True)
            return self.get_response(request)
