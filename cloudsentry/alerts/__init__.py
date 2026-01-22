"""Alerts module for CloudSentry."""

from .slack import SlackNotifier

__all__ = ["SlackNotifier"]
