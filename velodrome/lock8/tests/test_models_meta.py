"""Tests for meta behavior of models."""


def test_no_AttributeError_with_MetaJsonAccessorBuilder(lock, gps_tracking):
    """Test the current behaviour of MetaJsonAccessorBuilder."""
    orig = lock.private_tracking.time_stamp
    lock.private_tracking.time_stamp = 'something else'
    assert lock.private_tracking.time_stamp == orig


def test_exposed_attributes_from_base(gps_tracking):
    """Test the current behaviour of MetaJsonAccessorBuilder."""

    from velodrome.lock8.models import (BaseTracking, PrivateTracking,
                                        PublicTracking, Tracking)

    assert isinstance(BaseTracking.point, property)
    assert isinstance(PrivateTracking.point, property)
    assert isinstance(PublicTracking.point, property)
    assert isinstance(Tracking.point, property)

    assert gps_tracking.point is not None


def test_bicycle_serializers():
    from velodrome.lock8.serializers import (BaseLatestTrackingsSerializer,
                                             PrivateBicycleSerializer,
                                             PrivateLockSerializer)

    serializer = PrivateBicycleSerializer()
    assert 'latest_gps_accuracy' in serializer._declared_fields
    assert 'latitude' in serializer.fields
    assert 'latitude' in serializer.Meta.read_only_fields
    assert serializer.fields['latitude'].read_only
    assert set(BaseLatestTrackingsSerializer.Meta.fields).issubset(
        serializer.fields)

    serializer = PrivateLockSerializer()
    assert 'latitude' in serializer.fields
