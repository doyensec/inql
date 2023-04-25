# coding: utf-8
import json

from ..globals import montoya
from ..logger import log
from .storage import ConfigStore

DEFAULT_CONFIG = {
    # Valid levels: DEBUG, INFO (called 'verbose' in UI), WARN (called 'normal' in UI)
    'logging.level': 'WARN',
    # The depth of the auto-generated GraphQL requests
    'codegen.depth': 2,
    # The padding of the auto-generated GraphQL requests
    'codegen.pad': 2
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
          - project     - per-project settings (could be in-memory, if 'Temporary project' in use)
          - global      - global settings (the only persistent option in Community Edition)
          - effective   - look for key in project settings, if not found search in global and default options
        """
        if scope not in ('project', 'global', 'effective'):
            raise ValueError("Invalid scope provided: '%s'" % scope)

        if scope in ('project', 'effective'):
            value = self.project_options[key]
            if value:
                return value

        if scope in ('global', 'effective'):
            value = self.global_options[key]
            if value:
                return value

        if scope == 'effective':
            return DEFAULT_CONFIG.get(key, None)

        return None

    def set(self, key, value, scope='project'):
        """Set the config value.

        Valid scopes:
          - project
          - global
        """
        if scope == 'project':
            self.project_options[key] = value
        elif scope == 'global':
            self.global_options[key] = value
        else:
            raise ValueError("Invalid scope provided: '%s'" % scope)

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

    def reset(self, scope='project'):
        """Reset all config values.

        Valid scopes:
          - project
          - global
        """
        if scope == 'project':
            options = self.project_options
        elif scope == 'global':
            options = self.global_options
        else:
            raise ValueError("Invalid scope provided: '%s'" % scope)

        for key in options:
            del options[key]

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
