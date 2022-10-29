from setuptools import setup

version = '0.0.1dev0'

setup(
    name='velodrome',
    version=version,
    author='Noa Technologies, Inc',
    author_email='backend@noa.one',
    description='Backend API for Noa',
    url='https://github.com/lock8/velodrome',
    packages=('velodrome',),
    include_package_data=True,
)
