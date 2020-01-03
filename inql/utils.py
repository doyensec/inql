import re
import string, os, sys
import time
import threading


def string_join(*ss):
    """
    String joins with arbitrary lengthy parameters

    :param ss: strings to be joined
    :return: strings joined
    """
    return "".join(ss)


def mkdir_p(path):
    """
    Create Directory if it does not exist, exit otherwise
    :param path:
    :return:
    """
    try:
        os.makedirs(path)
    except:
        if os.path.isdir(path):
            pass
        else:
            raise


def wrap_open(method, exceptions = (OSError, IOError)):
    """Wrap Open method in order to create containing directories if they does not exist"""
    def fn(*args, **kwargs):
        try:
            mkdir_p(os.path.dirname(args[0]))
            return method(*args, **kwargs)
        except exceptions:
            sys.exit('Can\'t open \'{0}\'. Error #{1[0]}: {1[1]}'.format(args[0], sys.exc_info()[1].args))

    return fn


open = wrap_open(open)


def inherits_popup_menu(element):
    """
    Inherits popup menu on each and every child widgets.

    :param element: current widget.
    :return: None
    """
    element.setInheritsPopupMenu(True)
    try:
        for e in element.getComponents():
            inherits_popup_menu(e)
    except:
        pass


class AttrDict(dict):
    """
    HACK: this class will generate a class object with fields from a dict
    """
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


def override_headers(http_header, overrideheaders):
    """
    Overrides headers with the defined overrides.

    :param http_header: an HTTP header content
    :param overrideheaders: an overrideheaders object.
    :return: a new overridden headers string
    """
    ree = [(
        re.compile("^%s\s*:\s*[^\n]+$" % re.escape(header), re.MULTILINE),
        "%s: %s" % (header, val))
        for (header, val) in overrideheaders]
    h = http_header
    for find, replace in ree:
        hn = re.sub(find, replace, h)
        if hn == h:
            h = "%s\n%s\n" % (hn, str(replace))
        else:
            h = hn

    return h


def nop_evt(evt):
    """
    Do nothing on events

    :param evt: ignored
    :return: None
    """
    pass

def nop():
    """
    Do nothing

    :return: None
    """
    pass

stop_watch = False

def stop():
    global stop_watch
    stop_watch = True

def watch(execute=nop, interval=60):
    global stop_watch
    def async_run():
        try:
            while not stop_watch:
                execute()
                time.sleep(interval)
                sys.stdout.flush()
                sys.stderr.flush()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()

    t = threading.Thread(target=async_run)
    t.start()

def run_async(execute=nop):
    def async_run():
        try:
            execute()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
    threading.Thread(target=async_run).start()
