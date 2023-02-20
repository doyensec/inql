#!/usr/bin/env python
from __future__ import print_function

from inql.introspection import main, red, reset
from inql.utils import string_join

#if __name__ == "__main__":
#    try:
#        main()
#    except KeyboardInterrupt:
#        # Catch CTRL+C, it will abruptly kill the script
#        print(string_join(red, "Exiting...", reset))

try:
    main()
except KeyboardInterrupt:
    # Catch CTRL+C, it will abruptly kill the script
    print(string_join(red, "Exiting...", reset))
