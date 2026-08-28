"""Secret handling: a single redaction chokepoint and secret-input resolver.

Nothing in this CLI prints or logs a secret except through code that has first
passed it through :class:`~cryptnox_id_cli.secrets.redaction.Redactor`.
"""
