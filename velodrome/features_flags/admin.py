import json

from django.contrib import admin

from .models import ResourceModel, RuleAccessModel, RuleTemplateModel


@admin.register(ResourceModel)
class ResourceModelAdmin(admin.ModelAdmin):
    """Admin class for ResourceModel.
    """

    list_display = (
        "name",
        "read",
        "edit",
        "show",
        "default_dict_str",
    )

    list_display_links = (
        "name",
    )

    def default_dict_str(self, record: ResourceModel) -> str:
        return json.dumps(record.default_dict)


@admin.register(RuleTemplateModel)
class RuleTemplateModelAdmin(admin.ModelAdmin):
    """Admin class for RuleTemplateModel.
    """

    list_display = (
        "name", "full_name"
    )

    list_display_links = (
        "name",
    )

    def full_name(self, record: RuleTemplateModel) -> str:
        return str(record)


@admin.register(RuleAccessModel)
class RuleAccessModelAdmin(admin.ModelAdmin):
    """Admin class for RuleAccessModel.
    """

    list_display = (
        "full_name",
        "org_list",
    )

    list_filter = (
        "template",
    )

    def full_name(self, record: RuleAccessModel) -> str:
        return str(record)

    def org_list(self, record: RuleAccessModel) -> str:
        data = record.organizations.all().values_list(
            "name", flat=True
        ).iterator()
        return ", ".join(sorted(data))
