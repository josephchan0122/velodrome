from django.db.models import Q
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import RuleAccessModel


class RulesAccessView(APIView):
    """Rules and resource access configuration.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, **kwargs):
        """Collect access rules.
        """
        user = request.user if hasattr(request, "user") else None
        if not user or user.is_anonymous or user.is_staff:
            organizations = []
        else:
            organizations = user.get_descendants_organizations()

        result = {}
        org_filter = None
        if user.is_superuser:
            org_filter = Q()

        for organization in organizations:
            if org_filter is None:
                org_filter = Q(organizations=organization)
            else:
                org_filter |= Q(organizations=organization)
        if org_filter is None:
            rules = []
        else:
            rules = RuleAccessModel.objects.select_related(
                "template"
            ).filter(org_filter).iterator()

        fields = set()
        for rule in rules:
            content: dict = rule.full_content
            for resource, access in content.items():
                if resource in result:
                    fields.clear()
                    fields.update(result[resource])
                    fields.update(access)
                    for field in fields:
                        result[resource][field] = (
                                bool(access.get(field)) |
                                bool(result[resource].get(field))
                        )
                else:
                    result[resource] = access

        return Response(result)
