"""Tracks the user behind the current request so model signals can attribute audit entries."""

from contextvars import ContextVar

_current_user = ContextVar('current_user', default=None)


def get_current_user():
    return _current_user.get()


def set_current_user(user):
    return _current_user.set(user)


def reset_current_user(token):
    _current_user.reset(token)
