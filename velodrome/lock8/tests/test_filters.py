def test_RelatedBicyclesUUIDFilter(rf, bicycle_available, renter, bob):
    from velodrome.lock8.filters import RelatedBicyclesUUIDFilter

    f = RelatedBicyclesUUIDFilter()

    req = rf.get('/')
    req.user = renter
    assert list(f.queryset(req)) == [bicycle_available]

    req.user = bob
    assert f.queryset(req).count() == 0
