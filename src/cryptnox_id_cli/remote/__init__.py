"""Client for the Cryptnox remote PIV service.

The card stays in the holder's own reader; the service drives. This package
speaks the service's JSON frame protocol over a TLS WebSocket, relays the
commands it asks for to the local card, and returns each card answer verbatim.

The relay never interprets an operation on the card's behalf: it enforces a
fail-closed policy over what may be sent, and passes everything the policy
allows through untouched.
"""

from __future__ import annotations
