from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


def admin_required(view):
    """Only users with the Administrator role (or superusers) may use this view."""

    @login_required
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_administrator:
            raise PermissionDenied('Administrator role required.')
        return view(request, *args, **kwargs)

    return wrapper
