#!/usr/bin/env python
from setuptools import setup
import distutils.cmd
import distutils.log

def version():
   return os.popen('git describe --tags --dirty').read().strip()[1:]

class GenerateVersion(distutils.cmd.Command):
  """A custom command to create version file."""

  description = 'run Pylint on Python source files'
  user_options = []

  def initialize_options(self): pass
  def finalize_options(self): pass

  def run(self):
    """Run command."""
    with open('inql/__version__.py', 'w') as f:
      f.write("__version__ = '%s'" % version())


# The directory containing this file
import os 
HERE = os.path.dirname(os.path.realpath(__file__))


# The text of the README file
with open("%s/README.md" % HERE, 'r') as content_file:
    README = content_file.read()



setup(
   cmdclass={
      'generate_version': GenerateVersion,
   },
   name='inql',
   version=version(),
   description='Pentesting tool for GraphQL triage',
   long_description=README,
   long_description_content_type="text/markdown",
   author='Andrea Brancaleoni',
   author_email='andrea@doyensec.com',
   packages=['inql', 'inql.generators', 'inql.widgets', 'inql.actions'],
   scripts=['bin/inql'],
   install_requires=[],
)
