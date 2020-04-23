#!/usr/bin/env python
from setuptools import setup
import os

# The directory containing this file
import os 
HERE = os.path.dirname(os.path.realpath(__file__))


# The text of the README file
with open("%s/README.md" % HERE, 'r') as content_file:
    README = content_file.read()

setup(
   name='inql',
   version=os.popen('git describe --tags --dirty').read().strip()[1:],
   description='Pentesting tool for GraphQL triage',
   long_description=README,
   long_description_content_type="text/markdown",
   author='Andrea Brancaleoni',
   author_email='andrea@doyensec.com',
   packages=['inql', 'inql.generators', 'inql.widgets', 'inql.actions'],
   scripts=['bin/inql'],
   install_requires=[],
)
