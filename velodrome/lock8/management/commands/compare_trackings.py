# import datetime as dt
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('count', nargs='?', type=int)

    def handle(self, count, **options):
        from velodrome.lock8.models import ReadonlyTracking, Tracking

        errors = False

        ro_trackings = ReadonlyTracking.objects.all().order_by('?')[:count]
        other_trackings = Tracking.objects.filter(message_uuid__in=(
            t.uuid for t in ro_trackings
        ))
        for ro_tracking in ro_trackings:
            print('Checking uuid={}: '.format(ro_tracking.uuid), end='')
            try:
                other = other_trackings.get(message_uuid=ro_tracking.uuid)
            except Tracking.DoesNotExist:
                print('✘: missing')
                continue
            diff = ro_tracking.get_diff_to_tracking(other)
            if not diff:
                print('✔')
            else:
                print('✘')
                print(ro_tracking, other, diff, sep='\n')
                errors = True

        trackings = Tracking.objects.order_by('-timestamp')
        trackings = trackings[:count]
        ro_trackings = ReadonlyTracking.objects.filter(uuid__in=(
            t.message_uuid for t in trackings
        ))
        for other in trackings:
            message_uuid = other.message_uuid
            print('Reverse-checking message_uuid={}: '.format(message_uuid),
                  end='')
            try:
                ro_tracking = ro_trackings.get(uuid=message_uuid)
            except ReadonlyTracking.DoesNotExist:
                print('✘: missing')
                print(other)
                continue
            diff = ro_tracking.get_diff_to_tracking(other)
            if not diff:
                print('✔')
            else:
                print('✘')
                print(ro_tracking, other, diff, sep='\n')
                errors = True
        if errors:
            raise CommandError('Some checks failed')
