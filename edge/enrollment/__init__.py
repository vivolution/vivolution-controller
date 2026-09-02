"""Provider-neutral Vivolution Edge enrollment client."""

from .core import (
    AGENT_VERSION,
    EnrollmentError,
    EnrollmentMetadata,
    Identity,
    ProtectedState,
    consume_root_token_file,
    read_token_stream,
)

__all__ = (
    "AGENT_VERSION",
    "EnrollmentError",
    "EnrollmentMetadata",
    "Identity",
    "ProtectedState",
    "consume_root_token_file",
    "read_token_stream",
)
