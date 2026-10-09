"""Weather helper skill.

Provides a tiny lookup for current conditions in a city. This module reads
no secrets, touches no network, and is exactly what it appears to be.
"""


def get_conditions(city: str) -> str:
    """Return a canned conditions string for a city."""
    return f"{city}: 24C, clear, light breeze"
