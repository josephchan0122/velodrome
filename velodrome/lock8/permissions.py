from django.http import Http404
from rest_framework import exceptions, permissions
from rest_framework.permissions import SAFE_METHODS

from .models import ClientApp

default_viewset_actions = {'list', 'retrieve', 'create', 'update',
                           'partial_update', 'destroy', 'metadata'}


def check_scopes_are_allowed(request, perms):
    try:
        scopes = request.auth['scopes']
    except KeyError:
        return True
    except TypeError:
        # Expected with no authentication or when using tokens etc.
        return True
    if not scopes:
        return False
    for scope in scopes:
        try:
            granted_perms = ClientApp.PERMISSION_SCOPE_MAPPING[scope]
        except KeyError:
            return False
        if set(perms) <= granted_perms:
            return True
    return False


class CustomPermissions(permissions.BasePermission):
    def __init__(self, perms):
        self.perms = perms

    def has_permission(self, request, view):
        return (check_scopes_are_allowed(request, self.perms) and
                request.user.has_perms(self.perms))

    def has_object_permission(self, request, view, obj):
        return (check_scopes_are_allowed(request, self.perms) and
                request.user.has_perms(self.perms, obj))


class AnonCustomPermissions(CustomPermissions):
    authenticated_users_only = False


class DjangoObjectPermissions(permissions.DjangoObjectPermissions):
    perms_map = permissions.DjangoModelPermissions.perms_map.copy()
    perms_map['GET'] = ['%(app_label)s.view_%(model_name)s']

    def get_required_permissions(self, method, action, model_cls):
        app_label = model_cls._meta.app_label
        model_name = model_cls._meta.model_name
        if action is None:
            kwargs = {
                'app_label': app_label,
                'model_name': model_name
            }

            if method not in self.perms_map:
                raise exceptions.MethodNotAllowed(method)

            return [perm % kwargs for perm in self.perms_map[method]]

        if method in SAFE_METHODS:
            return [f'{app_label}.view_{model_name}_{action}']
        return [f'{app_label}.{action}_{model_name}']

    get_required_object_permissions = get_required_permissions

    def has_permission(self, request, view):
        # Workaround to ensure DjangoModelPermissions are not applied
        # to the root view when using DefaultRouter.
        if getattr(view, '_ignore_model_permissions', False):
            return True

        if hasattr(view, 'get_queryset'):
            queryset = view.get_queryset()
        else:
            queryset = getattr(view, 'queryset', None)

        assert queryset is not None, (
            'Cannot apply DjangoModelPermissions on a view that '
            'does not set `.queryset` or have a `.get_queryset()` method.'
        )
        action = (view.action if {view.action} - default_viewset_actions
                  else None)
        perms = self.get_required_permissions(
            request.method, action, queryset.model)
        user = request.user
        return (
            user and
            check_scopes_are_allowed(request, perms) and
            (user.is_authenticated or not
             self.authenticated_users_only) and
            (user.has_perms(perms))
        )

    def has_object_permission(self, request, view, obj):
        if hasattr(view, 'get_queryset'):
            queryset = view.get_queryset()
        else:
            queryset = getattr(view, 'queryset', None)

        assert queryset is not None, (
            'Cannot apply DjangoObjectPermissions on a view that '
            'does not set `.queryset` or have a `.get_queryset()` method.'
        )

        model_cls = queryset.model
        user = request.user

        action = (view.action if {view.action} - default_viewset_actions
                  else None)
        perms = self.get_required_object_permissions(
            request.method, action, model_cls)

        if not (check_scopes_are_allowed(request, perms) and
                user.has_perms(perms, obj)):
            # If the user does not have permissions we need to determine if
            # they have read permissions to see 403, or not, and simply see
            # a 404 response.

            if request.method in SAFE_METHODS:
                # Read permissions already checked and failed, no need
                # to make another lookup.
                raise Http404

            read_perms = self.get_required_object_permissions(
                'GET', None, model_cls)
            if not user.has_perms(read_perms, obj):
                raise Http404

            # Has read permissions.
            return False

        return True


class IsAuthenticated(permissions.BasePermission):
    """Allow access only to authenticated users."""

    def has_permission(self, request, view):
        if getattr(view, '_ignore_model_permissions', False):
            return True
        return request.user and request.user.is_authenticated


class IsAllowedToSeeTransitions(permissions.BasePermission):

    def has_permission(self, request, view):
        return True

    def has_object_permission(self, request, view, obj):
        perm = 'lock8.view_{}_transitions'.format(obj._meta.model_name)
        return (check_scopes_are_allowed(request, [perm]) and
                request.user.has_perm(perm, obj))


class AnonDjangoObjectPermissions(DjangoObjectPermissions):
    authenticated_users_only = False
