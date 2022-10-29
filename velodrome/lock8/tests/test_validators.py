from django.core.exceptions import ValidationError
import pytest


def test_validate_signup_domain_names():
    from velodrome.lock8.validators import validate_signup_domain_names

    with pytest.raises(ValidationError):
        validate_signup_domain_names('not a list')
    with pytest.raises(ValidationError) as excinfo:
        validate_signup_domain_names(['invalid'])
    assert excinfo.value.message == "'invalid' is not a valid domain name"
    validate_signup_domain_names([])
    validate_signup_domain_names(['example.org'])


def test_validate_alert_types():
    from velodrome.lock8.validators import validate_alert_types

    with pytest.raises(ValidationError):
        validate_alert_types('not a list')
    validate_alert_types([])


def test_organization_validation(org):
    from velodrome.lock8.models import Organization

    with pytest.raises(ValidationError) as excinfo:
        Organization(allowed_signup_domain_names='foo').full_clean()
    assert excinfo.value.message_dict['allowed_signup_domain_names'] == [
        "'foo' is not of type 'list' or 'tuple'"]
