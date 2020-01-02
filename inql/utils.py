import string, os, sys


def stringjoin(*ss):
	return string.join(ss)

def mkdir_p(path):
    try:
        os.makedirs(path)
    except:
        if os.path.isdir(path):
            pass
        else:
            raise


# Wrap open to create directory before opening a file
def wrap_open(method, exceptions = (OSError, IOError)):
    def fn(*args, **kwargs):
        try:
            mkdir_p(os.path.dirname(args[0]))
            return method(*args, **kwargs)
        except exceptions:
            sys.exit('Can\'t open \'{0}\'. Error #{1[0]}: {1[1]}'.format(args[0], sys.exc_info()[1].args))

    return fn


open = wrap_open(open)


def inheritsPopupMenu(element):
    element.setInheritsPopupMenu(True)
    try:
        for e in element.getComponents():
            inheritsPopupMenu(e)
    except:
        pass