from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets

from velodrome.lock8.views import (
    BaseModelViewSetMixin, SoftDeletedModelViewSetMixin,
)

from .models import TagDeclaration, TagGroup, TagInstance
from .serializers import (
    TagDeclarationSerializer, TagGroupSerializer, TagInstanceSerializer,
)


class TagGroupViewSet(BaseModelViewSetMixin,
                      SoftDeletedModelViewSetMixin,
                      viewsets.ModelViewSet):
    model = TagGroup
    serializer_class = TagGroupSerializer
    filter_backends = [DjangoFilterBackend, ]
    filterset_fields = ['uuid', ]


class TagDeclarationViewSet(BaseModelViewSetMixin,
                            SoftDeletedModelViewSetMixin,
                            viewsets.ModelViewSet):
    model = TagDeclaration
    serializer_class = TagDeclarationSerializer


class TagInstanceViewSet(BaseModelViewSetMixin,
                         SoftDeletedModelViewSetMixin,
                         viewsets.ModelViewSet):
    model = TagInstance
    serializer_class = TagInstanceSerializer
