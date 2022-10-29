"""pytest plugin to add options.

This can cause problems from conftest,
see http://pytest.org/latest/writing_plugins.html?highlight=pytest_addoption#_pytest.hookspec.pytest_addoption.
"""  # noqa
import math

import pytest

_orig_handlers = {}
"""Store original handlers, e.g. for publish_updates."""


def pytest_addoption(parser):
    parser.addoption('--dynamodb-test-url', action='store', default=None,
                     help='Run integration tests against DynamoDB.')
    parser.addoption('--run-migration-tests', action='store_true',
                     help='Run migration tests.')
    parser.addoption('--parametrize-image', action='store_true',
                     help='Parametrize images as png/jpg.')
    parser.addoption('--split-tests', action='store', type=int, choices=(1, 2),
                     help=('Split tests in half and run the specified group.'))
    parser.addoption('--run-slow-tests', action='store_true',
                     help=('Run slow tests.'))
    parser.addoption('--only-using-fixture', action='store',
                     help=('Run tests using a specific fixture only.'))


def noop(*args, **kwargs):
    pass


@pytest.fixture
def uses_publish_updates():
    from velodrome.lock8 import models

    orig = models.publish_updates
    assert orig is noop
    models.publish_updates = _orig_handlers['publish_updates']
    yield
    models.publish_updates = orig


def pytest_configure():
    from django.apps import apps
    if not apps.ready:
        # pytest --help/--version (pytest-django skips setup then).
        return

    from velodrome.lock8 import models
    global _orig_handlers

    _orig_handlers['publish_updates'] = models.publish_updates
    models.publish_updates = noop


@pytest.hookimpl
def pytest_runtest_setup(item):
    if ('slow' in item.keywords
            and not item.config.getoption('--run-slow-tests')):

        # Run the test anyway if it was provided via its nodeid as arg.
        if not any(x.startswith(item.nodeid) for x in item.config.args):
            pytest.skip('Not running slow tests (use --run-slow-tests)')


@pytest.hookimpl(hookwrapper=True)
def pytest_collection_modifyitems(config, items):
    """Handle --split-tests."""

    yield

    only_using_fixture = config.getoption('--only-using-fixture')
    if only_using_fixture:
        new_items = []
        for item in items:
            if only_using_fixture in item.fixturenames:
                new_items.append(item)
        items[:] = new_items

    split_group = config.getoption('--split-tests')
    if split_group:
        # Split by 30/70: the first tests are slower in general, also because
        # of requirering Docker.
        split = int(math.ceil(len(items) * 0.3))

        new_items = []
        for i, item in enumerate(items):
            if ('dynamodb_integration_test' in item.fixturenames or i < split):
                group = 1
            else:
                group = 2
            if group == split_group:
                new_items.append(item)

        print('split-tests: keeping {} tests (group {}, {} removed)'.format(
            len(new_items), split_group, len(items) - len(new_items)))
        items[:] = new_items


@pytest.fixture()
def dynamodb_integration_test(request, monkeypatch):
    ddb_url = request.config.getoption("--dynamodb-test-url")
    if not ddb_url:  # pragma: no cover
        pytest.skip('--dynamodb-test-url is not provided.')
        return

    from velodrome.lock8.dynamodb import session
    dynamodb = session.resource('dynamodb', endpoint_url=ddb_url)
    monkeypatch.setattr('velodrome.lock8.dynamodb.dynamodb', dynamodb)


@pytest.fixture
def migration_test(request):
    if not request.config.getoption("--run-migration-tests"):
        pytest.skip('--run-migration-tests is not provided.')
    request.getfixturevalue('transactional_db')


def pytest_generate_tests(metafunc):
    # Only parametrize "image" fixture when explicitly requested.
    if 'image_ext' in metafunc.fixturenames:
        exts = ['png']
        if metafunc.config.option.parametrize_image:
            exts += ['jpg']
        metafunc.parametrize('image_ext', exts, scope='function')

    if 'multi_db' in metafunc.fixturenames:
        # Enable Django's multi_db feature for tests globally.
        # Can be improved after
        # https://github.com/pytest-dev/pytest-django/pull/431.
        if 'transactional_db' in metafunc.fixturenames:
            from djanto.test import TransactionTestCase
            TransactionTestCase.multi_db = True
        else:
            from django.test import TestCase
            TestCase.multi_db = True

    if 'alert_type' in metafunc.fixturenames:
        from velodrome.lock8.models import Alert
        params = [
            t for t, _ in Alert.TYPES
            if t not in (Alert.BICYCLE_STOLEN, Alert.LOCK_ALARM_TRIGGERED)]
        params.extend(['lock.bat.low+alice', 'bicycle.ride_outside+zone'])
        metafunc.parametrize('alert_type', params, scope='function')
