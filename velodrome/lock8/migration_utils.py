"""Utility functions to create fixtures in migrations and tests."""
from django.conf import settings
from django.db.models.signals import post_migrate


def create_root_org(Organization, owner):
    root_org = Organization.objects.create(
        name='Noa',
        owner=owner,
        parent=None,
        level=0,
        lft=1,
        rght=2,
        tree_id=1,
    )
    Organization._root_org = root_org
    return root_org


def create_root_feedback_categories(Organization, FeedbackCategory):
    lock8 = Organization.objects.get(level=0)

    if FeedbackCategory.objects.filter(parent=None).exists():
        return
    mptt_args = {'tree_id': 1,
                 'level': 0,
                 'lft': 0,
                 'rght': 0}
    root = FeedbackCategory.objects.create(parent=None, name='root',
                                           **mptt_args)

    bicycle_node = FeedbackCategory.objects.create(
        name='bicycle', parent=root, **mptt_args)
    FeedbackCategory.objects.create(
        name='front-wheel', parent=bicycle_node, **mptt_args)
    FeedbackCategory.objects.create(
        name='rear-wheel', parent=bicycle_node, **mptt_args)
    FeedbackCategory.objects.create(
        name='seat', parent=bicycle_node, **mptt_args)
    FeedbackCategory.objects.create(
        name='gear', parent=bicycle_node, **mptt_args)
    FeedbackCategory.objects.create(
        name='chain', parent=bicycle_node, **mptt_args)
    FeedbackCategory.objects.create(
        name='handlebars', parent=bicycle_node, **mptt_args)
    FeedbackCategory.objects.create(
        name='brakes', parent=bicycle_node, **mptt_args)
    FeedbackCategory.objects.create(
        name='pedals', parent=bicycle_node, **mptt_args)

    device_node = FeedbackCategory.objects.create(
        name='device', parent=root, **mptt_args)
    FeedbackCategory.objects.create(
        name='lock', parent=device_node, **mptt_args)
    FeedbackCategory.objects.create(
        name='tracker', parent=device_node, **mptt_args)

    lock8.feedback_category_tree = root
    lock8.save()

    def rebuild_tree(app_config, *args, **kwargs):
        if app_config.label == 'lock8':
            FeedbackCategory = app_config.get_model('FeedbackCategory')
            FeedbackCategory.objects.rebuild()
            post_migrate.disconnect(rebuild_tree)

    post_migrate.connect(rebuild_tree, weak=False)


def create_bicycle_types(cls, owner):
    for ref, title in (('city_bike', 'City Bike'),
                       ('cargo_bike', 'Cargo Bike'),
                       ('cruiser', 'Cruiser'),
                       ('ducth_bike', 'Dutch Bike'),
                       ('e_bike', 'E-Bike')):
        cls.objects.get_or_create(reference=ref,
                                  title=title,
                                  owner=owner)


def migrate_pricing_scheme_ranges_to_cents(PricingScheme):
    # Convert amount to cents in PricingScheme.time_ranges.
    for pricing_scheme in PricingScheme.objects.filter(
            time_ranges__isnull=False):
        save = False
        for item in pricing_scheme.time_ranges:
            if item[2]:
                item[2] = item[2] * 100
                save = True
        if save:
            pricing_scheme.save()


def set_root_org_values(root_org, owner, OrganizationPreference):
    root_org.app_download_url = settings.FRONTEND_BASE_URL
    # NOTE: this is not really correct, but we have fixed it manually for
    # prod/test.
    root_org.user_email_logo = 'https://s3-eu-west-1.amazonaws.com/noa-email-templates/img/logo-noa-rider.png'  # noqa
    try:
        preference = root_org.preference
    except OrganizationPreference.DoesNotExist:
        preference = OrganizationPreference(
            organization=root_org,
            owner=owner,
            currency=settings.DEFAULT_CURRENCY,
            idle_bicycle_duration=settings.DEFAULT_IDLE_BICYCLE_DURATION,
        )
    preference.support_email = 'support@noa.one'
    root_org.save()
    preference.save()
