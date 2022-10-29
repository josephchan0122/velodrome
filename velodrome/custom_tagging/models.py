from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.query import Prefetch, Q
from django.forms.fields import UUIDField

from velodrome.lock8.models import (
    BaseModelMixin, OrganizationOwnedModelMixin, OwnerableModelMixin,
)


class TagGroup(BaseModelMixin):
    """The Tag class/type/family. Some upper-level meta-entity for tags.
    """

    name = models.CharField(max_length=128, db_index=True, unique=True)
    description = models.TextField(default='', blank=True, null=True)

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        if user.is_anonymous:
            return cls.objects.none()
        qs = cls.objects.all()

        # To show tag declarations available for organization of current user
        # TODO: Maybe move this logic to specific QuerySet method
        organizations = user.get_descendants_organizations()
        predicate = Q(
            organization__in=organizations
        )

        org_uuid = request.query_params.get('organization', None)
        if org_uuid:
            try:
                org_uuid = UUIDField().to_python(org_uuid)
                predicate &= Q(organization__uuid=org_uuid)
            except ValidationError:
                return cls.objects.none()
            predicate &= Q(organization__uuid=org_uuid)

        tag_declarations_of_org = TagDeclaration.objects.filter(predicate)
        return qs.prefetch_related(
            Prefetch(
                'declarations',
                queryset=tag_declarations_of_org
            )
        )

    def __str__(self):
        return 'TagGroup[{}]'.format(
            self.name,
        )

    def __repr__(self):
        return 'TagGroup(pk=%r, name=%r)' % (
            self.pk,
            self.name,
        )


class TagDeclaration(BaseModelMixin,
                     OwnerableModelMixin,
                     OrganizationOwnedModelMixin):
    """A declaration/description of tag that can be used to tag anything.
    What name it has, which group defined in TagGroup it belongs to.
    Organization specific.
    """

    name = models.CharField(max_length=128, db_index=True)
    description = models.TextField(default='', blank=True)
    group = models.ForeignKey(
        TagGroup,
        related_name='declarations',
        related_query_name='declaration',
        on_delete=models.CASCADE
    )
    color = models.CharField(
        max_length=7,
        blank=True,
        null=True,
    )
    organization = models.ForeignKey(
        'lock8.Organization',
        verbose_name='Organization',
        related_name='tags',
        related_query_name='tag',
        blank=True,
        null=True,
        on_delete=models.CASCADE,
    )

    class Meta(BaseModelMixin.Meta):
        unique_together = (('organization', 'name'), )

    def __str__(self):
        return 'TagDeclaration[{}] / TagGroup[{}] / Organization[{}]'.format(
            self.name,
            self.group.name,
            self.organization.pk,
        )

    def __repr__(self):
        return 'TagDeclaration(pk=%r, name=%r, group=%r)' % (
            self.pk,
            self.name,
            self.group,
        )


class TagInstance(BaseModelMixin,
                  OwnerableModelMixin):
    """Just M2M table to tag Bicycle/Lock/... with tags defined
    in TagDeclaration table.
    """

    declaration = models.ForeignKey(
        TagDeclaration,
        related_name='instances',
        related_query_name='instance',
        on_delete=models.CASCADE
    )

    # This is for binding records from different tables via GenericRelation
    content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT)
    object_id = models.PositiveIntegerField()
    target = GenericForeignKey('content_type', 'object_id')

    @classmethod
    def get_queryset(cls, request=None, **kwargs):

        user = request.user
        if user.is_anonymous:
            return cls.objects.none()

        organizations = user.get_descendants_organizations()
        predicate = Q(
            declaration__organization__in=organizations
        )

        org_uuid = request.query_params.get('organization', None)
        if org_uuid:
            try:
                org_uuid = UUIDField().to_python(org_uuid)
            except ValidationError:
                return cls.objects.none()
            predicate &= Q(declaration__organization__uuid=org_uuid)

        return cls.objects.filter(predicate).distinct()

    def __str__(self):
        return f'Tag[{self.declaration.name}]'

    def __repr__(self):
        return 'Tag(pk=%r, declaration=%r)' % (
            self.pk,
            self.declaration,
        )
