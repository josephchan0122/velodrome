"""
Integration tests for the base Docker image.

This gets run via 'make docker_test_integration', and does not use pytest or
other testing dependencies.
"""
from ctypes.util import find_library

import requests

assert requests.get('https://keysafe-cloud.appspot.com/').status_code == 200

gdal = find_library('gdal')
assert gdal.startswith('libgdal.so'), gdal
