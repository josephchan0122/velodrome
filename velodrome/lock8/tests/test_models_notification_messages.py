import json

from django_redis import get_redis_connection
import pytest


@pytest.mark.skip(reason='publish_updates on save is disabled')
def test_notification_messsage_updates_are_publised_with_alert(
        notification_message, fleet_operator, org, lock, commit_success):

    redis = get_redis_connection('publisher')
    pubsub = redis.pubsub()
    channel = '/{}/{}/notifications/'.format(org.uuid, fleet_operator.uuid)
    pubsub.subscribe(channel)
    message = pubsub.get_message()
    assert message == {'channel': channel.encode('utf-8'),
                       'data': 1,
                       'pattern': None,
                       'type': 'subscribe'}
    notification_message.send()
    commit_success()

    message = pubsub.get_message()
    assert sorted(list(message.keys())) == ['channel', 'data',
                                            'pattern', 'type']
    assert message['channel'] == channel.encode('utf-8')
    assert message['pattern'] is None
    assert message['type'] == 'message'

    assert json.loads(message['data'].decode('utf-8')) == {
        'topic': '/{}/{}/notifications/'.format(org.uuid, fleet_operator.uuid),
        'sender': 'alert',
        'message': {
            'alert_type': 'lock.bat.low',
            'causality_resource_type': 'lock',
            'causality_info': {'resource_type': 'lock'},
            'extra': {'lock_bleid': '4c4f434b385f3030303030303130888',
                      'lock_uuid': str(lock.uuid)},
            'message': 'alert',
            'state': notification_message.causality.state,
            'role': '',
            'roles': ['fleet_operator'],
            'uuid': str(notification_message.causality.uuid),
            'created': (notification_message.causality
                        .created.isoformat()[:-13] + 'Z'),
            'modified': (notification_message.causality
                         .modified.isoformat()[:-13] + 'Z'),
            'concurrency_version': (notification_message.causality
                                    .concurrency_version),
        }}


@pytest.mark.skip(reason='publish_updates on save is disabled')
def test_notification_messsage_updates_are_publised_with_task(
        notification_message, fleet_operator, org, lock, task1,
        commit_success):

    redis = get_redis_connection('publisher')
    pubsub = redis.pubsub()
    channel = '/{}/{}/notifications/'.format(org.uuid, fleet_operator.uuid)
    pubsub.subscribe(channel)
    message = pubsub.get_message()
    assert message == {'channel': channel.encode('utf-8'),
                       'data': 1,
                       'pattern': None,
                       'type': 'subscribe'}
    notification_message.causality = task1
    notification_message.send()
    commit_success()

    message = pubsub.get_message()
    assert sorted(list(message.keys())) == ['channel', 'data',
                                            'pattern', 'type']
    assert message['channel'] == channel.encode('utf-8')
    assert message['pattern'] is None
    assert message['type'] == 'message'

    assert json.loads(message['data'].decode('utf-8')) == {
        'topic': '/{}/{}/notifications/'.format(org.uuid, fleet_operator.uuid),
        'sender': 'task',
        'message': {
            'bicycle_uuid': None,
            'causality_info': {
                'alert_type': 'lock.bat.low',
                'resource_type': 'alert',
            },
            'causality_resource_type': 'alert',
            'completed_at': None,
            'remaining_distance': None,
            'severity': 'high',
            'context': {'alert_type': 'lock.bat.low'},
            'due': notification_message.causality.due.isoformat()[:-13] + 'Z',
            'is_due': True,
            'state': notification_message.causality.state,
            'role': 'mechanic',
            'uuid': str(notification_message.causality.uuid),
            'created': (notification_message.causality
                        .created.isoformat()[:-13] + 'Z'),
            'modified': (notification_message.causality
                         .modified.isoformat()[:-13] + 'Z'),
            'concurrency_version': (notification_message.causality
                                    .concurrency_version),
        }}


@pytest.mark.skip(reason='publish_updates on save is disabled')
def test_notification_messsage_updates_are_publised_with_feedback(
        notification_message, fleet_operator, org, lock, feedback,
        commit_success):

    redis = get_redis_connection('publisher')
    pubsub = redis.pubsub()
    channel = '/{}/{}/notifications/'.format(org.uuid, fleet_operator.uuid)
    pubsub.subscribe(channel)
    message = pubsub.get_message()
    assert message == {'channel': channel.encode('utf-8'),
                       'data': 1,
                       'pattern': None,
                       'type': 'subscribe'}
    notification_message.causality = feedback
    notification_message.send()
    commit_success()

    message = pubsub.get_message()
    assert sorted(list(message.keys())) == ['channel', 'data',
                                            'pattern', 'type']
    assert message['channel'] == channel.encode('utf-8')
    assert message['pattern'] is None
    assert message['type'] == 'message'

    assert json.loads(message['data'].decode('utf-8')) == {
        'topic': '/{}/{}/notifications/'.format(org.uuid, fleet_operator.uuid),
        'sender': 'feedback',
        'message': {
            'causality_info': {'resource_type': 'bicycle'},
            'causality_resource_type': 'bicycle',
            'message': 'It blew up.',
            'image': ('http://127.0.0.1:8000/' +
                      str(notification_message.causality.image)),
            'severity': 'high',
            'state': notification_message.causality.state,
            'uuid': str(notification_message.causality.uuid),
            'created': (notification_message.causality
                        .created.isoformat()[:-13] + 'Z'),
            'modified': (notification_message.causality
                         .modified.isoformat()[:-13] + 'Z'),
            'concurrency_version': (notification_message.causality
                                    .concurrency_version),
        }}


def test_topics_builder_for_notification_message(notification_message, org,
                                                 fleet_operator):
    from velodrome.lock8.dispatchers import build_publisher_topics

    assert sorted(build_publisher_topics(notification_message)) == sorted([
        ('/{}/{}/notifications/'.format(org.uuid, fleet_operator.uuid), False),
    ])
