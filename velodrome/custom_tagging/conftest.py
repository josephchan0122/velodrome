from velodrome.lock8.conftest import *  # noqa


@pytest.fixture  # noqa
def maintenance_tag_group():
    from .models import TagGroup
    return TagGroup.objects.create(
        name='Maintenance',
        description='Tags addressed to Crew Team',
    )


@pytest.fixture  # noqa
def fixme_tag(maintenance_tag_group, org, owner):
    from .models import TagDeclaration
    return TagDeclaration.objects.create(
        name='Fix me',
        description='Bring me to the service as soon as possible',
        group=maintenance_tag_group,
        color='#2596BE',
        organization=org,
        owner=owner
    )


@pytest.fixture  # noqa
def another_tag(maintenance_tag_group, another_org, owner):
    from .models import TagDeclaration
    return TagDeclaration.objects.create(
        name='Fix me',
        description='Bring me to ANOTHER service as soon as possible',
        group=maintenance_tag_group,
        color='#E28743',
        organization=another_org,
        owner=owner
    )


@pytest.fixture  # noqa
def fixme_tag_applied_to_bicycle(fixme_tag, bicycle, owner):
    from .models import TagInstance
    return TagInstance.objects.create(
        declaration=fixme_tag,
        target=bicycle,
        owner=owner
    )
