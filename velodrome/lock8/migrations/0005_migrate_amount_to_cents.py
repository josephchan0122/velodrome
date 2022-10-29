# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lock8', '0004_free_floating_fleet_pref'),
    ]

    operations = [
        migrations.AddField(
            model_name='pricingscheme',
            name='max_daily_charged_cents',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='rentalsession',
            name='cents',
            field=models.IntegerField(blank=True, null=True, verbose_name='Amount in cents'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='subscriptionplan',
            name='cents',
            field=models.IntegerField(null=True, verbose_name='Amount (per period) in cents'),
            preserve_default=False,
        ),

        migrations.AlterField(
            model_name='rentalsession',
            name='amount',
            field=models.DecimalField(blank=True, decimal_places=2, default=None, max_digits=9, null=True),
        ),
        migrations.AlterField(
            model_name='subscriptionplan',
            name='amount',
            field=models.DecimalField(decimal_places=2, max_digits=9, null=True, verbose_name='Amount (per period)'),
        ),
    ]
