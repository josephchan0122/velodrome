import logging

from django.db import migrations

logger = logging.getLogger(__name__)


def migrate_pending_payments_to_failed_state(apps, schema_editor):
    RentalSession = apps.get_model('lock8', 'RentalSession')

    for rs in RentalSession.objects.filter(
            payment_state='pending',
            state='closed'):
        logger.info('Converting rentalsession to failed payment_state: %r',
                    rs)
        rs.payment_state = 'failed'
        rs.save()


class Migration(migrations.Migration):

    dependencies = [
        ('lock8', '0053_organizationpreference_tax_percent'),
    ]

    operations = [
        migrations.RunPython(
            migrate_pending_payments_to_failed_state,
            reverse_code=migrations.RunPython.noop
        ),
    ]
