from django import http
from django.template.loader import get_template

ADMIN_500_TEMPLATE = 'lock8/admin/500.html'
CLIENT_500_TEMPLATE = 'lock8/client/500.html'


def handler500(request, template_name=None):
    template = (
        ADMIN_500_TEMPLATE
        if '/admin/' in request.path
        else CLIENT_500_TEMPLATE
    )
    fetched_template = get_template(template)
    return http.HttpResponseServerError(
        fetched_template.render({'request': request}),
        content_type='text/html'
    )
