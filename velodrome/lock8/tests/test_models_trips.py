from datetime import timedelta
import uuid


def test_trip_properties(trip, org, bicycle):
    assert trip.bicycle == bicycle
    assert trip.organization == org


def test_trip_annotate_with_speed(writable_trackings_db, trip,
                                  trip_without_duration):
    from velodrome.lock8.models import Trip

    trip_with_zero_duration = trip_without_duration
    trip_with_zero_duration.pk = 0
    trip_with_zero_duration.uuid = uuid.uuid4()
    trip_with_zero_duration.duration = timedelta(seconds=0)
    with writable_trackings_db():
        trip_with_zero_duration.save()

    qs = Trip.objects.annotate_with_speed()
    assert [x.speed for x in qs] == [None, 20.0, None]
