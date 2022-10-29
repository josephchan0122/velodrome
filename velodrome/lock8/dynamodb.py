from copy import deepcopy
from decimal import ROUND_DOWN, localcontext as decimal_localcontext
import logging
import os
from pprint import pformat
from typing import TYPE_CHECKING

from boto3.dynamodb.conditions import Key
from boto3.session import Session
from botocore.exceptions import ClientError
from django.conf import settings

if TYPE_CHECKING:
    from boto3.resources.base import ServiceResource as Boto3ServiceResource  # noqa: E501,F401

session = Session(region_name=settings.AWS_REGION_NAME)
dynamodb = session.resource('dynamodb')  # type: Boto3ServiceResource
logger = logging.getLogger(__name__)


def get_ddbtable_wrapped_name(name: str, is_testing: bool = None) -> str:
    if is_testing is None:
        is_testing = settings.IS_TESTER
    if is_testing:
        test_prefix = 'test__'
        if 'PYTEST_XDIST_WORKER' in os.environ:
            test_prefix += os.environ['PYTEST_XDIST_WORKER'] + '__'
    else:
        test_prefix = ''
    return f'{test_prefix}{name}-{settings.DYNAMODB_TABLE_SUFFIX}'


def get_ddbtable(name: str) -> dynamodb.Table:
    return dynamodb.Table(get_ddbtable_wrapped_name(name))


def recursive_get_expression(exp, recurse=None):
    if isinstance(exp, str):
        return exp
    if isinstance(exp, Key):
        return 'Key: {}'.format(exp.name)

    if recurse is None:
        recurse = recursive_get_expression

    if hasattr(exp, 'get_expression'):
        exp = exp.get_expression()
    if isinstance(exp, dict):
        exp = deepcopy(exp)
        for k, v in exp.items():
            exp[k] = recurse(v)
    elif isinstance(exp, tuple):
        exp = tuple(recurse(v) for v in exp)
    return exp


def query_table(table: dynamodb.Table, query: dict, select: str) -> dict:
    logger.debug('QUERY (%s): %s', select,
                 pformat(recursive_get_expression(query)))
    with decimal_localcontext() as context:
        context.rounding = ROUND_DOWN
        response = table.query(**query)
    logger.debug('RESPONSE (%s): %s', select, response)
    return response


def key_schema(hash=None, range=None):
    schema = []
    if hash is not None:
        schema.append({"KeyType": "HASH", "AttributeName": hash})
    if range is not None:
        schema.append({"KeyType": "RANGE", "AttributeName": range})
    return {"KeySchema": schema}


def attributes(**kwargs):
    return {"AttributeDefinitions": [
        {"AttributeName": name, "AttributeType": typ}
        for name, typ in kwargs.items()]}


def try_delete_tables(tables):
    for table in tables:
        try:
            table.delete()
        except ClientError as e:
            logger.error('Could not delete DynamoDB table: %s', e)
