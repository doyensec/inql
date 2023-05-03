# coding: utf-8
import json

from ..globals import montoya
from ..logger import log, set_log_level
from .storage import ConfigStore

DEFAULT_CONFIG = {
    ## Code generation
    # The depth of the auto-generated GraphQL requests
    'codegen.depth': 2,
    # The padding of the auto-generated GraphQL requests
    'codegen.pad': 4,

    ## Additional reporting
    # Export GraphQL introspection schema (JSON)
    'report.introspection': True,
    # Export GraphQL schema (SDL)
    'report.sdl': False,
    # Examine schema for cyclical references, produce the report
    'report.cycles': False,

    ## Points of Interest
    'report.poi': True,

    # How deep in the schema to look for PoI
    'report.poi.depth': 2,
    # Valid poi report formats: text, json, both
    'report.poi.format': 'text',

    # Various PoI categories - should match DEFAULT_CATEGORIES from
    # lib/GQLSpection/src/gqlspection/points_of_interest/keywords.py
    'report.poi.auth': True,
    'report.poi.privileged': True,
    'report.poi.pii': True,
    'report.poi.payment': True,
    'report.poi.database': True,
    'report.poi.debugging': True,
    'report.poi.files': True,
    'report.poi.deprecated': True,
    'report.poi.custom_scalars': True,

    # Custom keywords to look for during PoI report (newline-separated)
    'report.poi.custom_keywords': '',

    ## Logging & Debugging
    # Valid levels: DEBUG, INFO (called 'verbose' in UI), WARN (called 'normal' in UI)
    'logging.level': 'WARN',
}

def enabled_categories():
    """Return a list of enabled categories."""
    categories = [key.replace('report.poi.', '', 1) for key in DEFAULT_CONFIG.keys() if key.startswith('report.poi.') and config.get(key)]
    return categories

def set_logging_level(value):
    set_log_level(log, value)

CONFIG_HOOKS = {
    'logging.level': set_logging_level
}

# Note that Config only supports strings, integers and bools.
# Complex structures like header profile configuration should be serialized as a JSON string:
#
# For example, header profiles could be stored like this:
#
# [
#   ['ProjectX', [
#       ['Authorization', 'Bearer JWTJWTJWT'],
#       ['Cookie', 'super-secret-cookie=admin']
#     ],
#   ['ProjectY', [
#       ['Cookie', 'csrf-token=abcdef'],
#       ['X-CSRF-Token', 'abcdef']
#     ]
# ]
#
# Then you can store them in profile/global settings like this:
#
#   config.set('headers.profiles', json.dumps(profile_configuration), scope='project')
#
# And later read & work with these settings like this:
#
#   profiles = json.loads(config['headers.profiles'])
#
#   profile_names = [profile['name'] for profile in profiles]
#
#   for profile_name, headers in profiles:
#       for header_name, header_value in headers:
#           print(header_name, header_value)


class Config(object):
    _global_store  = None
    _project_store = None

    @property
    def global_options(self):
        if not self._global_store:
            self._global_store = ConfigStore(montoya.persistence().preferences())
        return self._global_store

    @property
    def project_options(self):
        if not self._project_store:
            self._project_store = ConfigStore(montoya.persistence().extensionData())
        return self._project_store

    def get(self, key, scope='effective'):
        """Get the config value.

        Valid scopes:
          - project          - per-project settings (could be in-memory, if 'Temporary project' in use)
          - effective        - look for key in project settings, if not found search in global and default options
          - global           - global settings (the only persistent option in Community Edition)
          - effective_global - look for key in global settings, if not found search in default options
        """
        log.debug("Looking for config value: %s (scope: %s)", key, scope)
        if scope not in ('project', 'global', 'effective', 'effective_global'):
            raise ValueError("Invalid scope provided: '%s'" % scope)

        if scope in ('project', 'effective'):
            value = self.project_options[key]
            if value is not None:
                return value

        if scope in ('global', 'effective', 'effective_global'):
            value = self.global_options[key]
            if value is not None:
                log.debug("Found config value in global settings: %s=%s", key, value)
                return value

        if scope in ('effective', 'effective_global'):
            log.debug("Looking for config value in default settings: %s", key)
            return DEFAULT_CONFIG.get(key, None)

        log.debug("Config value not found: %s", key)
        return None

    def set(self, key, value, scope='project'):
        """Set the config value.

        Valid scopes:
          - project
          - global
        """
        log.debug("Setting config value: %s=%s (scope: %s, type: %s)", key, value, scope, type(value))

        if scope == 'project':
            log.debug("Setting config value in project settings: %s=%s", key, value)
            self.project_options[key] = value
            log.debug("Done setting config value in project settings: %s=%s", key, value)
        elif scope == 'global':
            log.debug("Setting config value in global settings: %s=%s", key, value)
            self.global_options[key] = value
            log.debug("Done setting config value in global settings: %s=%s", key, value)
        else:
            raise ValueError("Invalid scope provided: '%s'" % scope)

        log.debug("Contents of project settings:")
        for k in self.project_options.keys():
            log.debug("  %s=%s", k, self.project_options[k])
        log.debug("Contents of global settings:")
        for k in self.global_options.keys():
            log.debug("  %s=%s", k, self.global_options[k])

        # Call config hook, if any
        if key in CONFIG_HOOKS:
            CONFIG_HOOKS[key](self.get(key, 'effective'))

    def delete(self, key, scope='project'):
        """Delete config value.

        Valid scopes:
          - project
          - global
        """
        if scope == 'project':
            del self.project_options[key]
        elif scope == 'global':
            del self.global_options[key]
        else:
            raise ValueError("Invalid scope provided: '%s'" % scope)

        # Call config hook, if any
        if key in CONFIG_HOOKS:
            CONFIG_HOOKS[key](self.get(key, 'effective'))

    def reset(self, scope='project'):
        """Reset all config values.

        Valid scopes:
          - project
          - global
        """
        options = self.project_options if scope == 'project' else self.global_options
        for key in options.keys():
            self.delete(key, scope)

    def items(self, scope='project'):
        """List config items in scope (debugging).

        Valid scopes:
          - project
          - global
          - default
        """
        if scope == 'project':
            keys = self.project_options.keys()
            return [(k, self.project_options[k]) for k in keys]
        elif scope == 'global':
            keys = self.global_options.keys()
            return [(k, self.global_options[k]) for k in keys]
        elif scope == 'default':
            keys = DEFAULT_CONFIG.keys()
            return [(k, DEFAULT_CONFIG[k]) for k in keys]
        else:
            raise ValueError("Invalid scope provided: '%s'" % scope)

    def debug_contents(self):
        log.info("project settings: %s", json.dumps(dict(self.items('project')), indent=4))
        log.info("global settings: %s",  json.dumps(dict(self.items('global')),  indent=4))
        log.info("default settings: %s", json.dumps(dict(self.items('default')), indent=4))


config = Config()
