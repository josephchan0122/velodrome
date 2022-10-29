from django.db import IntegrityError, connection
from django.db.migrations.executor import MigrationExecutor
import pytest


@pytest.fixture(scope='session')
def django_db_use_migrations(request, django_db_use_migrations):
    if request.config.getoption("--run-migration-tests"):
        return True
    return django_db_use_migrations


def test_migrate_amount_to_cents(org, owner):
    """For 0006_migrate_amount_to_cents_data"""
    from velodrome.lock8.models import PricingScheme
    from velodrome.lock8.migration_utils import (
        migrate_pricing_scheme_ranges_to_cents
    )

    PricingScheme.objects.create(organization=org, owner=owner, name='p1',
                                 time_ranges=((0, 60, 2, False, 0),
                                              (60, None, 1, False, 0)))
    PricingScheme.objects.create(organization=org, owner=owner, name='p2',
                                 time_ranges=[(0, None, 0, False, 0)])

    migrate_pricing_scheme_ranges_to_cents(PricingScheme)

    assert [['p1', [[0, 60, 200, False, 0], [60, None, 100, False, 0]]],
            ['p2', [[0, None, 0, False, 0]]]] == sorted([
                [x.name, x.time_ranges]
                for x in PricingScheme.objects.all()], key=lambda x: x[0])


def test_organization_get_root_org_constraint(migration_test, root_org, owner):
    from velodrome.lock8.models import Organization

    assert Organization.objects.count() == 1  # root_org

    with pytest.raises(IntegrityError) as excinfo:
        Organization.objects.create(name='A second root', owner=owner,
                                    parent=None)
    assert 'single_tree_id' in excinfo.value.args[0]


def test_migrations_rollback(migration_test):
    """Test rollback of last five migrations."""

    import logging
    logger = logging.getLogger(__name__)

    app = 'lock8'

    executor = MigrationExecutor(connection)
    root_nodes = executor.loader.graph.root_nodes()
    root_node = [x for x in root_nodes if x[0] == app]
    assert len(root_node) == 1
    backwards_plan = executor.loader.graph.backwards_plan(root_node[0])
    back_nodes = [x for x in backwards_plan if x[0] == 'lock8']
    back_without_initial = [
        x for x in back_nodes if not x[1].startswith(
            ('0001_initial', '0002_initial', '0003_initial'))]
    if not back_without_initial:
        pytest.skip('Nothing to test yet')
    migrate_to = back_without_initial[:5][-1]
    logger.info('Migrating to %s', migrate_to)
    executor.migrate([migrate_to])

    # Reload to make "flush" during teardown work.
    executor.loader.build_graph()

    # Migrate forwards again.
    # Not really necessary if this is run last.
    # leaf_nodes = executor.loader.graph.leaf_nodes(app=app)
    # executor.migrate(leaf_nodes)

# NOTE: new tests should go above the last one!
