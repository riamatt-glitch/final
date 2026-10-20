from django.contrib import messages
from django.http import Http404
from django.shortcuts import redirect

from .audit import reset_current_user, set_current_user


class CurrentUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = set_current_user(getattr(request, 'user', None))
        try:
            return self.get_response(request)
        finally:
            reset_current_user(token)


class MissingRecordMiddleware:
    """
    Turn a "not found" on a record page (e.g. a stale link to a finding that was deleted or
    re-created when the demo data was reset) into a redirect to the current list with a message.
    """

    LIST_FOR_PREFIX = [
        ('/findings/', 'finding_list', 'finding'),
        ('/assets/', 'asset_list', 'asset'),
        ('/vulnerabilities/', 'vulnerability_list', 'vulnerability record'),
        ('/tasks/', 'task_list', 'remediation task'),
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if not isinstance(exception, Http404) or request.method != 'GET' or not request.user.is_authenticated:
            return None
        for prefix, list_view, label in self.LIST_FOR_PREFIX:
            if request.path.startswith(prefix):
                messages.warning(request, f'That {label} no longer exists. It may have been deleted, or the data '
                                          f'was reset since the page you came from was loaded. Here is the current list.')
                return redirect(list_view)
        return None
