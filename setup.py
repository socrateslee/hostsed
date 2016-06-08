#!/usr/bin/env python

sdict = {
    'name': 'hostsed',
    'version': "0.1.0",
    'packages': ['hosts'],
    'zip_safe': False,
    'author': 'lichun',
    'scripts': ['hostsed'],
    'classifiers': [
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Programming Language :: Python']
}

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(**sdict)
