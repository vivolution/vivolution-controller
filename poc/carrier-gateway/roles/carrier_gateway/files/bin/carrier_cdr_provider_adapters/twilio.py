"""Twilio external billing corroboration adapter.

This module owns every Twilio-specific receipt field, schema, signing-key, and
binding rule.  The carrier CDR collector loads it through the versioned adapter
contract and remains unaware of those provider details.
"""

from __future__ import annotations

import re
from typing import Any

ADAPTER_API_VERSION = "poc.vivolution.ae/carrier-cdr-provider-adapter/v1"
PROVIDER_PROFILE = "twilio"
SIGNING_KEY_ID = "twilio:authoritative-call-log"
CORROBORATION_SCHEMA = "poc.vivolution.ae/twilio-call-log-corroboration/v1"
CORROBORATION_STATUS = "TWILIO_EXACTLY_ONE_BILLED_CALL"
VERIFIED_STATUS = "EXACTLY_ONE_BILLED_CALL_CORROBORATED"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PAYLOAD_KEYS = {
    "billedCallCount",
    "billedDurationSeconds",
    "carrierRecordDigest",
    "destinationDigest",
    "observedAt",
    "requestId",
    "schema",
    "status",
    "twilioAccountDigest",
    "twilioCallSidDigest",
}


def verify(context: Any) -> dict[str, str]:
    payload, receipt_digest = context.verify_signed_receipt(
        expected_key_id=SIGNING_KEY_ID,
        payload_keys=PAYLOAD_KEYS,
    )
    if (
        payload["schema"] != CORROBORATION_SCHEMA
        or payload["status"] != CORROBORATION_STATUS
        or payload["requestId"] != context.request_id
        or payload["destinationDigest"] != context.destination_digest
        or payload["carrierRecordDigest"] != context.carrier_record_digest
        or type(payload["billedCallCount"]) is not int
        or payload["billedCallCount"] != 1
        or type(payload["billedDurationSeconds"]) is not int
        or payload["billedDurationSeconds"] != context.billed_duration_seconds
        or payload["observedAt"] != context.observed_end_timestamp
        or not isinstance(payload["twilioAccountDigest"], str)
        or not DIGEST.fullmatch(payload["twilioAccountDigest"])
        or not isinstance(payload["twilioCallSidDigest"], str)
        or not DIGEST.fullmatch(payload["twilioCallSidDigest"])
    ):
        context.reject(
            "signed Twilio call log does not prove exactly one billed call"
        )
    return {
        "adapterApiVersion": ADAPTER_API_VERSION,
        "providerProfile": PROVIDER_PROFILE,
        "receiptDigest": receipt_digest,
        "signingKeyId": SIGNING_KEY_ID,
        "status": VERIFIED_STATUS,
    }
