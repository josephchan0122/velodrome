def test_is_admin_or_fleet_operator(anon):
    from velodrome.lock8.predicates import is_at_least_fleet_operator

    assert not is_at_least_fleet_operator(anon)
