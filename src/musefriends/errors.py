"""Structured domain errors for muse-friends."""
from __future__ import annotations


class FriendsError(Exception):
    """Application-level error with a stable code and HTTP status."""

    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
