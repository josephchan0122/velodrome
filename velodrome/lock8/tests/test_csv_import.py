from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_fb_bulk_bicyle_import(django_admin_client, admin_user, bicycle_types,
                               fb_bicycle_file, root_org, mailoutbox):
    from velodrome.lock8.models import Bicycle, BicycleModel

    response = django_admin_client.post(
        reverse_query('admin:fb_bulk_import'),
        data={'import_file': fb_bicycle_file,
              'organization': root_org.id})
    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject.startswith('Bulk Bicycle import ')
    assert email.recipients() == [admin_user.email]
    assert 'Bicycles created 4' in email.body
    assert 'Bicycles skipped 0' in email.body

    assert BicycleModel.objects.count() == 2

    model = BicycleModel.objects.filter(name='43 ST').get()

    assert Bicycle.objects.count() == 4

    bicycle = Bicycle.objects.get(name='1001')

    assert bicycle.organization == root_org
    assert bicycle.description == 'FCC14K00115'
    assert bicycle.model == model


def test_generic_bulk_bicyle_import(django_admin_client, admin_user, root_org,
                                    bicycle_model, generic_bicycle_file,
                                    mailoutbox):
    from velodrome.lock8.models import Bicycle

    response = django_admin_client.post(
        reverse_query('admin:generic_bulk_import'),
        data={'import_file': generic_bicycle_file,
              'organization': root_org.id,
              'model': bicycle_model.pk})

    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject.startswith('Bulk Bicycle import ')
    assert email.recipients() == [admin_user.email]
    assert 'Bicycles created 15' in email.body
    assert 'Bicycles skipped 0' in email.body

    assert Bicycle.objects.count() == 15

    bicycle = Bicycle.objects.get(serial_number='00001')

    assert bicycle.organization == root_org
    assert bicycle.name == 'toto1'
    assert bicycle.description == ';aslkd'
    assert bicycle.model == bicycle_model


def test_generic_bulk_bicyle_import_skipped(django_admin_client, admin_user,
                                            owner, bicycle_model, root_org,
                                            generic_bicycle_file, mailoutbox):
    from velodrome.lock8.models import Bicycle

    for serial_number, name, description in (('00001', 'toto1', ';aslkd'),
                                             ('00002', 'toto2',
                                              'sadjlkj askdj alskdj')):
        Bicycle.objects.create(owner=owner,
                               organization=root_org,
                               model=bicycle_model,
                               serial_number=serial_number,
                               name=name,
                               description=description)

    response = django_admin_client.post(
        reverse_query('admin:generic_bulk_import'),
        data={'import_file': generic_bicycle_file,
              'organization': root_org.id,
              'model': bicycle_model.pk})

    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject.startswith('Bulk Bicycle import ')
    assert email.recipients() == [admin_user.email]
    assert 'Bicycles created 13' in email.body
    assert 'Bicycles skipped 2' in email.body

    assert Bicycle.objects.count() == 15


def test_generic_bulk_bicyle_import_error(django_admin_client, admin_user,
                                          owner, bicycle_model, mailoutbox,
                                          generic_bicycle_error_file,
                                          root_org):
    from velodrome.lock8.models import Bicycle

    response = django_admin_client.post(
        reverse_query('admin:generic_bulk_import'),
        data={'import_file': generic_bicycle_error_file,
              'organization': root_org.id,
              'model': bicycle_model.pk})

    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject.startswith('Generic Bicycle bulk import ')
    assert 'failed' in email.subject
    assert email.recipients() == [admin_user.email]
    assert ("Could not import spreadsheet because of this error:"
            " Cannot resolve keyword 'does_not_exist'"
            " into field.") in email.body

    assert Bicycle.objects.count() == 0
