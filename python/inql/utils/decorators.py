# coding: utf-8
import functools
import inspect
import traceback
from functools import wraps
from threading import Thread

from ..globals import callbacks
from ..logger import log
from ..utils.ui import visual_error


# TODO: We should save pointers to all threads in order to make sure they are closed during extension's unloading
def threaded(fn):
    """Decorator which causes function to be executed in a new tread."""
    def wrapper(*args, **kwargs):
        thread = Thread(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread

    return wrapper


def _unroll_exceptions(f, name):

    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except:
            log.error("An exception in class {} (it won't be re-raised!)".format(name))
            traceback.print_exc(file=callbacks.getStderr())
            callbacks.getStderr().flush()
    return wrapper


def unroll_exceptions(cls):
    for name, method in inspect.getmembers(cls, inspect.ismethod):
        setattr(cls, name, _unroll_exceptions(method, cls.__name__))
    return cls



def single(func):
    """Decorator for Java action handlers, ignores exceptions.

    Super opinionated, **only works for class methods**, assuming that class has self.lock = threading.Lock()
    TODO: Make the decorator more generic, so that it can work for regular functions (without `self` as well).
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.lock.acquire(False):
            return None

        # lock acquired successfully
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            log.debug("An exception occured during silent execution (single): %s", str(e))
        finally:
            # executes before return in all branches
            self.lock.release()
        return None
    return wrapper


def single_with_error_handling(func):
    """Decorator for Java action handlers, calls visual_error on exception.

    Super opinionated, only works for class methods, assuming that class has self.lock = threading.Lock()
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.lock.acquire(False):
            return None

        # lock acquired successfully
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            log.error("An exception occured during execution (single_weh): %s", str(e))
            visual_error(str(e))
        finally:
            # executes before return in all branches
            self.lock.release()
        return None
    return wrapper
