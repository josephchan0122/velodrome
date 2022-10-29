from collections import OrderedDict

import pytest
from rest_framework.exceptions import ValidationError


def test_PricingSchemeSerializer():
    from velodrome.lock8.serializers import PricingSchemeSerializer

    serializer = PricingSchemeSerializer()
    assert sorted(list(serializer.fields.keys())) == sorted([
        'url', 'created', 'modified',
        'uuid', 'concurrency_version', 'state', 'name', 'description',
        'max_daily_charged_cents', 'time_ranges', 'owner',
        'organization', 'bicycle_model'])


def test_PrivateBicycleSerializer():
    from velodrome.lock8.serializers import PrivateBicycleSerializer

    serializer = PrivateBicycleSerializer()
    latitude = serializer.fields['latitude']
    assert latitude.source == 'private_tracking.gps_latitude'


def test_PublicBicycleSerializer():
    from velodrome.lock8.serializers import PublicBicycleSerializer

    serializer = PublicBicycleSerializer()
    latitude = serializer.fields['latitude']
    assert latitude.source == 'public_tracking.gps_latitude'


def test_PrivateLockSerializer():
    from velodrome.lock8.serializers import PrivateLockSerializer

    serializer = PrivateLockSerializer()
    latitude = serializer.fields['latitude']
    assert latitude.source == 'private_tracking.gps_latitude'


def test_PublicLockSerializer(lock):
    from velodrome.lock8.serializers import PublicLockSerializer

    serializer = PublicLockSerializer()
    latitude = serializer.fields['latitude']
    assert latitude.source == 'public_tracking.gps_latitude'


@pytest.mark.db
@pytest.mark.parametrize('user,expect_private', (
    ('admin_user', True), ('fleet_operator', False), ('renter', False),
    ('renter_and_admin_user', True), ('admin_user_and_renter', True),
    ('admin_of_org_and_admin_user', True)))
def test_correct_serializer_for_private_public(request, user, expect_private):
    from velodrome.lock8.jwt_extensions import (
        JSONWebTokenAuthentication, jwt_payload_handler)
    from velodrome.lock8.serializers import (
        BicycleBaseSerializer, PrivateBicycleSerializer,
        PublicBicycleSerializer,
        LockBaseSerializer, PrivateLockSerializer, PublicLockSerializer)

    user = request.getfixturevalue(user)
    user = JSONWebTokenAuthentication().authenticate_credentials(
        jwt_payload_handler(user))

    serializer = BicycleBaseSerializer.get_serializer_class_for_user(user)
    if expect_private:
        assert serializer is PrivateBicycleSerializer
    else:
        assert serializer is PublicBicycleSerializer

    serializer = LockBaseSerializer.get_serializer_class_for_user(user)
    if expect_private:
        assert serializer is PrivateLockSerializer
    else:
        assert serializer is PublicLockSerializer


def test_user_of_organization_serializer(rf, mocker):
    from velodrome.lock8.models import User
    from velodrome.lock8.serializers import UserOfOrganizationSerializer

    # Test serializer out of request context
    serializer = UserOfOrganizationSerializer()
    qs = User.objects
    mock = mocker.Mock()
    mocker.patch(
        'velodrome.lock8.serializers.UserSerializer.optimize_queryset',
        return_value=mock)
    serializer.optimize_queryset(qs)
    assert not mock.prefetch_related.called

    serializer.context['request'] = rf.get('/some/path')
    serializer.context['request'].query_params = {'organization': 'some-uuid'}
    serializer.optimize_queryset(qs)
    assert mock.prefetch_related.called


def test_password_forgot_with_duplicate_emails(db):
    from velodrome.lock8.models import User
    from velodrome.lock8.serializers import PasswordForgotSerializer

    User.objects.create(email='duplicate@example.com', username='user1')
    u2 = User.objects.create(email='duplicate@example.com', username='user2')

    s = PasswordForgotSerializer()
    assert s.validate({'email': 'duplicate@example.com'}) == {
        'email': 'duplicate@example.com',
    }
    assert s.user == u2


def test_zone_serializer_with_thresholds(rf):
    from velodrome.lock8.serializers import ZoneSerializer
    serializer = ZoneSerializer(context={'request': rf.get('/some/path')})
    fields = OrderedDict({'high_threshold': '100', 'low_threshold': '10'})
    assert serializer.validate(fields) == fields
    assert serializer.validate_low_threshold(100)
    assert serializer.validate_high_threshold(100)
    with pytest.raises(ValidationError):
        serializer.validate_low_threshold(-100)
    with pytest.raises(ValidationError):
        serializer.validate_high_threshold(-100)
    with pytest.raises(ValidationError):
        serializer.validate(
            OrderedDict({'high_threshold': '30', 'low_threshold': '500'})
        )
