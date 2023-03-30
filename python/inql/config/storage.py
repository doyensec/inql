# coding: utf-8
class ConfigStore(dict):
    """Dict-like wrapper around Burp's per-session/global key-value storage.

    Expects a single argument which can be one of these:

    - global Java preference store: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/persistence/Preferences.html
    - PersistedObject, per-project store: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/persistence/PersistedObject.html

    Supports boolean, integer and string values. Returns None if key not present.
    """
    store = None

    def __init__(self, store):
        super(ConfigStore, self).__init__()

        # Global or per-session key value storage
        self.store = store

    def __getitem__(self, key):
        """Access a key in the dictionary using the square bracket notation.

        Unlike normal dictionary, never raises KeyError and returns None if the key is not present in key-value store.
        """
        value = self.store.getBoolean(key)
        if value is None:
            value = self.store.getInteger(key)
            if value is None:
                value = self.store.getString(key)
        return value

    def __setitem__(self, key, value):
        """Set a value for a key in the dictionary using the square bracket notation.

        Only supports bool, int and str value types. Raises ValueError otherwise.
        """
        # Make sure we only ever have one value for a given key
        del self[key]

        if isinstance(value, bool):
            self.store.setBoolean(key, value)
        elif isinstance(value, int):
            self.store.setInteger(key, value)
        elif isinstance(value, str):
            self.store.setString(key, value)
        else:
            raise ValueError("Value must be a bool, int, or str")

    def __delitem__(self, key):
        """Delete a key from the dictionary using the del keyword."""
        if self.store.getBoolean(key) is not None:
            self.store.deleteBoolean(key)
        if self.store.getInteger(key) is not None:
            self.store.deleteInteger(key)
        if self.store.getString(key) is not None:
            self.store.deleteString(key)

    def __contains__(self, key):
        """Check if the dictionary contains a given key."""
        return (self.store.getBoolean(key) is not None
                or self.store.getInteger(key) is not None
                or self.store.getString(key) is not None)

    def keys(self):
        """Return sorted list of keys present in the dictionary."""
        keys = set()
        keys.update(self.store.booleanKeys())
        keys.update(self.store.integerKeys())
        keys.update(self.store.stringKeys())
        return sorted(keys)

    def __iter__(self):
        """Get an iterator over the keys of the dictionary."""
        return iter(self.keys())

    def __len__(self):
        """Get the number of key-value pairs in the dictionary."""
        return len(self.keys())
