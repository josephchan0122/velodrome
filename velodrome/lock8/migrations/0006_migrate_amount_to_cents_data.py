# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations
from django.db.models import F


def migrate_amount_to_cents(apps, schema_editor):
    from velodrome.lock8.migration_utils import (
        migrate_pricing_scheme_ranges_to_cents)

    RentalSession = apps.get_model('lock8', 'RentalSession')
    PricingScheme = apps.get_model('lock8', 'PricingScheme')
    SubscriptionPlan = apps.get_model('lock8', 'SubscriptionPlan')

    RentalSession.objects.update(cents=F('amount') * 100)
    PricingScheme.objects.update(max_daily_charged_cents=F(
        'max_daily_charged_amount') * 100)
    SubscriptionPlan.objects.update(cents=F('amount') * 100)

    migrate_pricing_scheme_ranges_to_cents(PricingScheme)


class Migration(migrations.Migration):

    dependencies = [
        ('lock8', '0005_migrate_amount_to_cents'),
    ]

    operations = [
        migrations.RunPython(migrate_amount_to_cents,
                             reverse_code=migrations.RunPython.noop),
    ]
