import string, os, sys


def string_join(*ss):
    """
    String joins with arbitrary lengthy parameters

    :param ss: strings to be joined
    :return: strings joined
    """
    return string.join(ss)


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