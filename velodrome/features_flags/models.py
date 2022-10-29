import typing

from django.contrib.postgres.fields import JSONField
from django.core.exceptions import ValidationError
from django.db import models

from .const import (
    FF_ACCESS_RULE_TABLE, FF_ORGANIZATION_RULE_TABLE, FF_RESOURCE_TABLE,
    FF_RULE_TPL_TABLE,
)


def extract_resource_names(content: dict) -> typing.Iterable[str]:
    """Recursive name search
    """
    if content:
        for field, access_conf in content.items():
            yield field
            if "include" in access_conf:
                yield from extract_resource_names(access_conf["include"])


def validate_rules(content: dict):
    """Pre-save checking.
    """
    if not isinstance(content, dict):
        raise ValidationError("Content have to be a dict.")

    names = set(extract_resource_names(content))
    av_names = set(
        ResourceModel.objects.all().values_list(
            "name", flat=True
        ).iterator()
    )
    wrong_names = names - av_names
    if wrong_names:
        raise ValidationError(
            "Unknown resources: {}".format(", ".join(wrong_names))
        )


class ResourceModel(models.Model):
    """Resources
    """

    name = models.CharField("Name", max_length=128)
    read = models.BooleanField("Readable", default=True)
    show = models.BooleanField("Showable", default=True)
    edit = models.BooleanField("Editable", default=True)

    class Meta:
        db_table = FF_RESOURCE_TABLE
        verbose_name = "Resource name"
        ordering = unique_together = ["name"]

    def __str__(self) -> str:
        """Info
        """
        base = []
        if self.read:
            base.append("readable")
        if self.edit:
            base.append("editable")
        if self.show:
            base.append("showable")

        base = "/".join(base)
        return f"{self.name} ({base})"

    def __repr__(self) -> str:
        return str(self)

    @property
    def default_dict(self) -> typing.Dict[str, bool]:
        """Default resource rules.
        """
        return {
            field.name: True
            for field in self._meta.fields
            if (
                isinstance(field, models.BooleanField) and
                getattr(self, field.name, None)
            )
        }


class RuleTemplateModel(models.Model):
    """Template of access rules
    """
    name = models.CharField("Name", max_length=128)
    content = JSONField(default=dict, verbose_name="Rules")

    class Meta:
        db_table = FF_RULE_TPL_TABLE
        verbose_name = "Rule template"
        ordering = unique_together = ["name"]

    def __repr__(self) -> str:
        return str(self)

    def __str__(self) -> str:
        names = set(extract_resource_names(self.content))
        return f"Template '{self.name}' resources: {len(names)}"

    def clean(self, *args, **kwargs):
        result = super().clean(*args, **kwargs)
        validate_rules(self.content)
        return result


class RuleAccessModel(models.Model):
    """Rulse access configuration.
    """
    template = models.ForeignKey(
        RuleTemplateModel,
        verbose_name="Template",
        on_delete=models.CASCADE
    )
    organizations = models.ManyToManyField(
        "lock8.Organization",
        related_name="features_flags_rules",
        db_table=FF_ORGANIZATION_RULE_TABLE
    )
    content = JSONField(
        default=dict, blank=True, verbose_name="Advanced rules"
    )

    class Meta:
        db_table = FF_ACCESS_RULE_TABLE
        verbose_name = "Access rule"
        ordering = ["-template__name"]

    @property
    def full_content(self) -> dict:
        """Template rules + advanced rules
        """
        data = self.template.content or {}
        if self.content:
            data.update(self.content)
        return data

    def __str__(self) -> str:
        names = set(extract_resource_names(self.full_content))
        return f"Rules '{self.template.name}' resources: {len(names)}"

    def __repr__(self) -> str:
        return str(self)

    def clean(self, *args, **kwargs):
        result = super().clean(*args, **kwargs)
        validate_rules(self.content)
        return result
