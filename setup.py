#!/usr/bin/env python
from setuptools import setup

setup(
   name='inql',
   version='0.0.1',
   description='Pentesting tool for GraphQL triage',
   author='Andrea Brancaleoni',
   author_email='andrea@doyensec.com',
   packages=['inql', 'inql.generators'],
   scripts=['bin/inql'],
   install_requires=[],
)
