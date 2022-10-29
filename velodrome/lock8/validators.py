import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator, RegexValidator

imei_regex = re.compile(r'\d{15}')
validate_imei = RegexValidator(regex=imei_regex)

iccid_regex = re.compile(r'\d{20}')
validate_iccid = RegexValidator(regex=iccid_regex)

sid_regex = re.compile(r'[a-fA-F\d]{32}')
validate_sid = RegexValidator(regex=sid_regex)


NoneType = type(None)


def validate_signup_domain_names(value):
    if not isinstance(value, (list, tuple)):
        msg = "{!r} is not of type 'list' or 'tuple'".format(value)
        raise ValidationError(msg)

    emailV = EmailValidator()
    for val in value:
        is_valid = emailV.validate_domain_part(domain_part=val)
        if not is_valid:
            msg = '{!r} is not a valid domain name'.format(val)
            raise ValidationError(msg)


def validate_alert_types(value):
    from velodrome.lock8.models import Alert

    if not isinstance(value, (list, tuple)):
        msg = "{!r} is not of type 'list' or 'tuple'".format(value)
        raise ValidationError(msg)

    for alert_type in value:
        if alert_type not in {t for t, _ in Alert.TYPES}:
            msg = '{!r} is not a valid Alert type'.format(alert_type)
            raise ValidationError(msg)


def validate_alert_types_to_task(value):
    from velodrome.lock8.models import Alert, FeedbackCategory

    if not isinstance(value, dict):
        msg = "{!r} is not of type 'dict'".format(value)
        raise ValidationError(msg)

    if not value:
        return

    for alert_type in value:
        if alert_type not in {t for t, _ in Alert.TYPES}:
            msg = '{!r} is not a valid Alert type'.format(alert_type)
            raise ValidationError(msg)

    for severity in value.values():
        if severity not in {s for s, _ in FeedbackCategory.SEVERITIES}:
            msg = '{!r} is not a valid Severity type'.format(severity)
            raise ValidationError(msg)


def validate_alert_type_to_role_mapping(value):
    from velodrome.lock8.models import Affiliation, Alert

    if not isinstance(value, dict):
        msg = "{!r} is not of type 'dict'".format(value)
        raise ValidationError(msg)

    for alert_type in value:
        if alert_type not in {t for t, _ in Alert.TYPES}:
            msg = '{!r} is not a valid Alert type'.format(alert_type)
            raise ValidationError(msg)

    allowed_role_set = {r for r, _ in Affiliation.ROLES}
    for roles in value.values():
        if not isinstance(roles, list):
            msg = 'Roles {!r} must be given as list'.format(roles)
            raise ValidationError(msg)
        for role in roles:
            if role not in allowed_role_set:
                msg = '{!r} is not a valid Role type'.format(role)
                raise ValidationError(msg)


def _validate_time_range(prefix, time_range, is_last=False):
    from velodrome.lock8.models import PricingSchemeRange

    if not isinstance(time_range, (list, tuple)):
        raise ValidationError(f'{prefix} is not a list.')
    try:
        pricing_scheme_range = PricingSchemeRange(*time_range)
    except TypeError:
        raise ValidationError(f'{prefix} is not a list with 5 entries.')
    if not isinstance(pricing_scheme_range.lower_duration,
                      (float, int)):
        raise ValidationError(f'{prefix}: lower_duration is not a decimal.')
    if is_last:
        if pricing_scheme_range.upper_duration is not None:
            raise ValidationError(f'{prefix}: upper_duration must be null.')
    else:
        if not isinstance(pricing_scheme_range.upper_duration, (float, int)):
            raise ValidationError(
                f'{prefix}: upper_duration is not a decimal.')
        if (pricing_scheme_range.lower_duration >=
                pricing_scheme_range.upper_duration):
            raise ValidationError(
                f'{prefix}: upper_duration must be greater than lower_duration.')  # noqa: E501
    if not isinstance(pricing_scheme_range.cents, int):
        raise ValidationError(f'{prefix}: cents is not a integer.')
    if pricing_scheme_range.cents < 0:
        raise ValidationError(f'{prefix}: cents is not positive.')
    if not isinstance(pricing_scheme_range.prorated, bool):
        raise ValidationError(
            f'{prefix}: prorated must be a boolean.')
    if not isinstance(pricing_scheme_range.prorated_duration,
                      (int, NoneType)):
        raise ValidationError(
            f'{prefix}: prorated_duration must be null or an integer.')
    if (pricing_scheme_range.prorated and
            isinstance(pricing_scheme_range.prorated_duration, int) and
            not pricing_scheme_range.prorated_duration):
        raise ValidationError(
            f'{prefix}: prorated_duration cannot be 0 if prorated is True.')
    return pricing_scheme_range


def validate_time_ranges(value):
    """
    `time_ranges` must be a list of :py:const::PricingSchemeRange.
    PricingSchemeRanges must be continuous.
    The last :py:const::PricingSchemeRange must have a `upper_duration`
    to None.
    """
    from velodrome.lock8.models import PricingSchemeRange

    if not isinstance(value, (list, tuple)):
        raise ValidationError(f'time_ranges {value!r} is not a list.')
    if not value:
        # (non-)blank gets validated separately.
        return

    for i, item in enumerate(value[:-1]):
        prefix = f'Item #{i}'
        pricing_scheme_range = _validate_time_range(prefix, item)
        if i > 0:
            previous_pricing_scheme_range = PricingSchemeRange(*value[i-1])
            if (previous_pricing_scheme_range.upper_duration !=
                    pricing_scheme_range.lower_duration):
                raise ValidationError(
                    '{}: duration is not contiguous: {} != {}.'.format(
                        prefix,
                        previous_pricing_scheme_range.upper_duration,
                        pricing_scheme_range.lower_duration))

    latest_item = value[-1]
    prefix = 'Last item'
    latest_pricing_scheme_range = _validate_time_range(prefix, latest_item,
                                                       is_last=True)
    if len(value) > 1:
        previous_latest_pricing_scheme_range = PricingSchemeRange(*value[-2])
        if (previous_latest_pricing_scheme_range.upper_duration !=
                latest_pricing_scheme_range.lower_duration):
            raise ValidationError(
                '{}: duration is not contiguous: {} != {}.'.format(
                    prefix,
                    previous_latest_pricing_scheme_range.upper_duration,
                    latest_pricing_scheme_range.lower_duration))


def validate_l10n_description(value):
    """Required for migration 0016_add_payment_descriptions.py."""


def validate_payment_description(value):
    if not isinstance(value, dict):
        raise ValidationError(f"{value} is not of type 'dict'")
    required_fields = ('title', 'description', 'short_description',
                       'fine_print')
    # amount is deprecated
    optional_fields = ('restriction', 'amount')
    all_fields = set(required_fields) | set(optional_fields)

    for language, local_desc in value.items():
        if language not in (code for code, _ in settings.LANGUAGES):
            raise ValidationError(f'{language} is not a supported language')
        if not isinstance(local_desc, dict):
            raise ValidationError(
                f"Value for key {language} is not of type 'dict'")
        extra_fields = set(local_desc) - all_fields
        if extra_fields:
            raise ValidationError(
                f'Extra fields found: {", ".join(extra_fields)}',
                code='unknown_field')

        missing_fields = []
        for local_key in required_fields:
            local_value = local_desc.get(local_key, '')
            if not local_value and not str(local_value):
                missing_fields.append(local_key)

        if missing_fields:
            raise ValidationError(
                'The following entries are required: {}'.format(
                    ', '.join(missing_fields)), code='missing_fields')
