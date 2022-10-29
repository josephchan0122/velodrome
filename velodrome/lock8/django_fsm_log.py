from django_fsm_log.backends import SimpleBackend


class DryRunReadyBackend(SimpleBackend):
    @staticmethod
    def post_transition_callback(sender, instance, name, source, target,
                                 method_kwargs=None, **kwargs):
        dry_run = (method_kwargs.get('dry_run', False) if
                   method_kwargs is not None else False)

        if dry_run:
            return

        return SimpleBackend.post_transition_callback(
            sender, instance, name, source, target, **kwargs)
