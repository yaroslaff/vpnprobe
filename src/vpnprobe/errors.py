"""Public vpnprobe exceptions."""


class ProbeError(Exception):
    """Base exception suitable for concise CLI diagnostics."""


class ConfigurationError(ProbeError):
    """A probe input or runtime option is invalid."""


class SubscriptionError(ProbeError):
    """A subscription cannot be downloaded or parsed safely."""
