from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = """Extract collected trackings of telit and send
    a spreadsheet by email.
    """
    can_import_settings = True

    def add_arguments(self, parser):
        parser.add_argument('email')

    def handle(self, *args, **options):
        from velodrome.lock8.utils import export_telit_trackings
        return export_telit_trackings(options['email'])
