try:
    from inql.__version__ import __version__
except ImportError:
    __version__ = 'undefined'


def burp_extension():
    print("testing here")

    import platform
    if platform.system() == "Java":
        from inql.burp_ext.extender import BurpExtender
