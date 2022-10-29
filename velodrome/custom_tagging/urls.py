from velodrome.lock8.router import Router

from .views import TagDeclarationViewSet, TagGroupViewSet, TagInstanceViewSet

router = Router()

router.register(
    r'tag_groups',
    TagGroupViewSet,
    basename='tag_group'
)
router.register(
    r'tag_declarations',
    TagDeclarationViewSet,
    basename='tag_declaration'
)
router.register(
    r'tag_instances',
    TagInstanceViewSet,
    basename='tag_instance'
)

router.urls.sort(key=lambda x: x.pattern.name)

urlpatterns = router.urls
