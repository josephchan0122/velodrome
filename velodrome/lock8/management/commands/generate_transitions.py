from os.path import join

from django.apps import apps
from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    can_import_settings = True

    def handle(self, *args, **kwargs):
        from django.conf import settings

        ftype = 'png'
        app = 'lock8'
        layout = 'circo'
        transitions_dir = join(settings.DOCS_DIR, 'fsm_transitions')

        for mtuple in apps.get_app_config(app).models.items():
            mname, mclass = mtuple[0], mtuple[1]
            fname = join(transitions_dir, '{}.{}'.format(mname.lower(), ftype))
            if hasattr(mclass, 'transitions'):
                call_command(
                    'graph_transitions',
                    '{}.{}'.format(app, mname),
                    outputfile=fname,
                    layout=layout
                )
