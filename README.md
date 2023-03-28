# InQL v5.0 beta

This branch contains the new InQL version which is almost a complete rewrite. Some functionality is broken and some
has been deprecated. To avoid surprises use latest stable release for now: https://github.com/doyensec/inql/releases/

On the other hand, if you want to contribute bug fixes or new features, this version is what you need as the 4.x branch
will only receive fixes from now on.

# Installation

General requirements:

Burp:

- Only the latest Burp is supported
- Both "Professional" and "Community" editions should work

Java:
- Montoya API requires Java 17+

## Building the InQL extension from git

1. Install Java 17+, for example in Debian-based distros:

```bash
$ sudo apt install -y openjdk-17-jdk
$ java --version
openjdk 17.0.6 2023-01-17
```

2. Clone the repo and pull submodules:

```bash
$ git clone https://github.com/doyensec/inql
$ cd inql
$ git checkout dev
$ git submodule init
$ git submodule update
```

3. Build the InQL extension:

```bash
$ ./gradlew
```

Load the file `build/InQL.jar` into Burp as a Java extension.

## Setting up development environment

First, set up a virtual environment with Python 2.7 (for Jython compatibility). Note that headers are needed to build
libraries with `pip`. For example, with virtualenv:

```bash
$ sudo apt install -y python2.7 python2.7-dev python2-setuptools-whl python2-pip-whl python3-virtualenv
$ virtualenv -p python2.7 ./venv/
```

Using [venv](https://docs.python.org/3.10/library/venv.html), [pyenv](https://github.com/pyenv/pyenv), etc will also
work.

Once you have the venv set up, activate it and install development requirements:

```bash
$ . ./venv/activate
$ pip install -r requirements_dev.txt
```

Install the GQLSpection from a submodule (as a development library so you can edit it directly):

```bash
$ pip install -e lib/GQLSpection/
```

Install pre-commit script to automatically run checks before each commit:

```bash
$ pre-commit install
```

Now a bunch of tests, including isort and pylint, should run on each commit. However, it will also change the files
if necessary and cancel commit in this case for you to inspect. So, make sure to check what's up, manually add the
changes (`git add`) and run `git commit` again (as the original commit didn't go through).

Your environment is ready for development of InQL! Note that GQLSpection requires its own setup. Oh, and if the
GQLSpection submodule gets out of date you'll see a message about it in `git status`. Fix it by running:

```bash
$ git submodule update
```

(this can also be done automatically when needed by modifying `~/.gitconfig`)

# Credits

_Author and original maintainer:_ Andrea Brancaleoni ([@nJoyneer](https://twitter.com/nJoyneer) - [thypon](https://github.com/thypon))

_Current maintainer:_ Andrew Konstantinov ([@execveat](https://infosec.exchange/@execveat))

This project was made with love in [Doyensec Research island](https://doyensec.com/research.html).
