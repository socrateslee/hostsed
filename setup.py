#!/usr/bin/env python

long_description = ""

try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except:
    pass

sdict = {
    'name': 'hostsed',
    'version': "0.4.0",
    'packages': ['hosts'],
    'zip_safe': False,
    'author': 'lichun',
    'url': 'https://github.com/socrateslee/hostsed',
    'scripts': ['hostsed'],
    'long_description': long_description,
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
