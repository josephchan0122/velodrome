import uuid

from velodrome.lock8.saml_api import extract_user_data


def test_saml_response_attrs(admin_user, org, settings):
    """Checking the saml attributes and user creation.
    """
    idp = "noa_google"
    attrs = {}

    res_org, res_user = extract_user_data(idp, attrs)
    assert not res_org and not res_user

    attrs = {
        "last_name": ["Test"],
        "first_name": ["Test user"],
        "department": [org.name],
        "email": [admin_user.email]
    }

    res_org, res_user = extract_user_data(idp, attrs)

    assert res_org and res_user
    assert res_org.pk == org.pk
    assert res_user.pk == admin_user.pk

    attrs = {
        "last_name": ["Test"],
        "first_name": ["Test user"],
        "department": [org.name],
        "email": [f"{uuid.uuid4()}@example.com"]
    }

    res_org, res_user = extract_user_data(idp, attrs)

    assert res_org and res_user
    assert res_org.pk == org.pk
    assert res_user.pk
    assert res_user.pk != admin_user.pk
    assert res_user.first_name and res_user.last_name and res_user.username
    res_user.save()
