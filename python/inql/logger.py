# coding: utf-8
import logging
import sys


class DebugOrInfo(logging.Filter):
    """Custom log filter that only matches DEBUG or INFO levels."""
    def filter(self, record):
        return record.levelno in (logging.DEBUG, logging.INFO)


def get_logger():
    """Returns centralized logger."""
    logger = logging.getLogger('InQL')
    set_log_level(logger, 'INFO')

    return logger

def set_log_level(logger, level):
    """Sets log level and generates handlers to pass DEBUG (if enabled) and INFO to stdout and WARN / ERR to stderr."""
    logger.setLevel(level)

    formatter = logging.Formatter('[thread#%(thread)d %(filename)s:%(lineno)d :: %(funcName)s()]    %(message)s')

    handler_stdout = logging.StreamHandler(sys.stdout)
    handler_stdout.setFormatter(formatter)
    handler_stdout.setLevel(logging.DEBUG)
    handler_stdout.addFilter(DebugOrInfo())

    handler_stderr = logging.StreamHandler(sys.stderr)
    handler_stderr.setFormatter(formatter)
    handler_stderr.setLevel(logging.WARNING)

    # Jython / Python 2.7 do not have logger.handlers.clear(), but we can remove handlers like this:
    del logger.handlers[:]

    logger.addHandler(handler_stdout)
    logger.addHandler(handler_stderr)

# Centralized log handler that gets used across InQL
log = get_logger()
