def test_check_scopes_are_allowed():
    from velodrome.lock8.permissions import check_scopes_are_allowed

    class FakeRequest:
        auth = {}
    fake_request = FakeRequest()

    assert check_scopes_are_allowed(fake_request, [])

    fake_request.auth = None
    assert check_scopes_are_allowed(fake_request, [])
