import uuid

from django.core.exceptions import ValidationError
import pytest


def test_client_app(org, owner):
    from velodrome.lock8.models import Affiliation, ClientApp, User

    name = 'Dat app'
    inactive_user = User.objects.create(
        username='{}:{}'.format(org.uuid, name)
    )
    Affiliation.objects.create(organization=org,
                               user=inactive_user,
                               role=Affiliation.ADMIN)

    remote_uuid = uuid.uuid4()
    client_app = ClientApp.objects.create(
        name=name,
        label='Dat Label',
        organization=org,
        scopes=['bicycle:read'],
        remote_uuid=remote_uuid,
        user=inactive_user,
        owner=owner,
    )
    assert client_app.created
    assert client_app.modified
    assert client_app.scopes == ['bicycle:read']
    assert client_app.uuid
    assert client_app.organization == org
    assert client_app.remote_uuid == remote_uuid
    assert client_app.user == inactive_user
    assert client_app.name == 'Dat app'
    assert client_app.label == 'Dat Label'


def test_client_app_constraint(org, owner):
    from velodrome.lock8.models import Affiliation, ClientApp, User

    name = 'Dat app'
    inactive_user = User.objects.create(
        username='{}:{}'.format(org.uuid, name)
    )
    Affiliation.objects.create(organization=org,
                               user=inactive_user,
                               role=Affiliation.ADMIN)

    remote_uuid = uuid.uuid4()
    ClientApp.objects.create(
        name=name,
        label='Dat Label',
        organization=org,
        scopes=['bicycle:read'],
        remote_uuid=remote_uuid,
        user=inactive_user,
        owner=owner,
    )
    client_app = ClientApp(
        name=name,
        label='Dat Label',
        organization=org,
        scopes=['bicycle:read'],
        remote_uuid=remote_uuid,
        user=inactive_user,
        owner=owner,
    )
    with pytest.raises(ValidationError):
        client_app.full_clean()
