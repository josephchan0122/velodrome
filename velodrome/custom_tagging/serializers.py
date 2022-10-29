from generic_relations.relations import GenericRelatedField
from rest_framework import serializers

from velodrome.lock8.models import Bicycle
from velodrome.lock8.serializers import (
    BaseHyperlinkedModelSerializer,
    OrganizationOwnedHyperlinkedModelSerializer,
    OwnerableHyperlinkedModelSerializer,
)

from .models import TagDeclaration, TagGroup, TagInstance


class TagGroupSerializer(BaseHyperlinkedModelSerializer):

    declarations = serializers.SerializerMethodField()

    class Meta:
        model = TagGroup
        fields = (
            'name',
            'description',
            'declarations',
        )
        extra_kwargs = {
            'url': {
                'view_name': 'custom-tagging:tag_group-detail',
                'lookup_field': 'uuid'
            },
        }

    def get_declarations(self, instance):
        return EmbeddedTagDeclarationInfoSerializer(
            instance.declarations,
            context=self.context,
            many=True,
            read_only=True
        ).data


class TagDeclarationSerializer(BaseHyperlinkedModelSerializer,
                               OwnerableHyperlinkedModelSerializer,
                               OrganizationOwnedHyperlinkedModelSerializer):

    owner = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = TagDeclaration
        fields = (
            'name',
            'description',
            'group',
            'color',
            'organization',
        )
        extra_kwargs = {
            'url': {
                'view_name': 'custom-tagging:tag_declaration-detail',
                'lookup_field': 'uuid'
            },
            'group': {
                'view_name': 'custom-tagging:tag_group-detail',
                'lookup_field': 'uuid'
            },
            'organization': {
                'view_name': 'lock8:organization-detail',
                'lookup_field': 'uuid'
            },
        }


class TagInstanceSerializer(BaseHyperlinkedModelSerializer,
                            OwnerableHyperlinkedModelSerializer):

    target = GenericRelatedField(
        {
            Bicycle: serializers.HyperlinkedRelatedField(
                lookup_field='uuid',
                view_name='lock8:bicycle-detail',
                queryset=Bicycle.objects.all(),
            ),
        }
    )
    owner = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = TagInstance
        fields = (
            'declaration',
            'target',
        )
        extra_kwargs = {
            'url': {
                'view_name': 'custom-tagging:tag_instance-detail',
                'lookup_field': 'uuid'
            },
            'declaration': {
                'view_name': 'custom-tagging:tag_declaration-detail',
                'lookup_field': 'uuid'
            },
        }

    def optimize_queryset(self, qs):
        return qs.select_related('declaration').prefetch_related('target')


class EmbeddedTagDeclarationInfoSerializer(serializers.Serializer):
    """Read-only serializer for showing TagDeclaration information inside
    the TagGroup response body.
    """
    uuid = serializers.UUIDField()
    name = serializers.CharField()
    description = serializers.CharField()
    color = serializers.CharField()

    class Meta:
        read_only_fields = fields = (
            'uuid',
            'name',
            'description',
            'color',
        )


class EmbeddedTagInfoSerializer(serializers.Serializer):
    """Read-only serializer for showing extended TagInstance info inside
    the tagged object response body.
    """
    uuid = serializers.UUIDField()
    tag_declaration_uuid = serializers.UUIDField(
        source='declaration.uuid',
    )
    tag_declaration_name = serializers.CharField(
        source='declaration.name',
    )
    tag_declaration_color = serializers.CharField(
        source='declaration.color',
    )

    class Meta:
        read_only_fields = fields = (
            'uuid',
            'tag_declaration_uuid',
            'tag_declaration_name',
            'created',
        )

    def optimize_queryset(self, qs):
        return qs.select_related('declaration')
