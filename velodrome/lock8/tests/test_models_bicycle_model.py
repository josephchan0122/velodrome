from django.core.exceptions import ValidationError
import pytest


def test_bicycle_model_model(org, owner, city_bike, photo, bicycle):
    from velodrome.lock8.models import BicycleModel

    bicycle_model = BicycleModel.objects.create(
        organization=org,
        name='Fast',
        type=city_bike,
        photo=photo,
        owner=owner,
    )

    assert bicycle_model.organization == org
    assert bicycle_model.name == 'Fast'
    assert bicycle_model.type == city_bike
    assert bicycle_model.photo == photo
    assert bicycle_model.state == 'new'
    assert bicycle_model.alert_types_to_task == {}
    assert bicycle_model.bicycle_count == 0

    bicycle.model = bicycle_model
    bicycle.save()

    assert bicycle_model.bicycle_count == 1

    bicycle.lock = None
    bicycle.retire()

    assert bicycle_model.bicycle_count == 0


@pytest.mark.parametrize('pref_and_test_vals', (
    ('alert_types_to_task', (
        ['foo'], {'lock.foo': 'high'},
        {'lock.bat.low': 'low', 'bicycle.bike_stolen': 'thing'}
    )),
))
def test_bicycle_model_validation(bicycle_model, pref_and_test_vals):
    pref, test_vals = pref_and_test_vals
    for test_val in test_vals:
        setattr(bicycle_model, pref, test_val)
        with pytest.raises(ValidationError):
            bicycle_model.full_clean()


def test_bicycle_model_deletion(org, owner, bicycle, bicycle_model):
    bicycle.model = bicycle_model
    bicycle.save()

    with pytest.raises(ValidationError):
        bicycle_model.delete()

    bicycle.delete()

    bicycle_model.delete()
