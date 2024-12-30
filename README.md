# InQL v5.0 - Burp Extension for Advanced GraphQL Testing

[![Doyensec Research Island](https://img.shields.io/static/v1?logo=data:image/png;base64,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&link=https://doyensec.com/research.html&message=Research%20Island&&label=Doyensec&color=purple)](https://doyensec.com/research.html)
![GitHub](https://img.shields.io/github/license/doyensec/inql?logo=github&color=darkgreen)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/doyensec/inql?label=latest%20release&logo=github)
![GitHub Release Date](https://img.shields.io/github/release-date/doyensec/inql?display_date=published_at&logo=github)
![GitHub milestone](https://img.shields.io/github/milestones/progress/doyensec/inql/3?logo=github&label=progress+towards+next+release)
[![dev branch ahead by](https://img.shields.io/github/commits-difference/doyensec/inql?base=master&head=dev&label=dev+branch+ahead+by&color=bright&logo=github)](https://github.com/doyensec/inql/tree/dev)
[![GitHub contributors](https://img.shields.io/github/contributors/doyensec/inql?logo=github&color=black)](AUTHORS)
[![GitHub issues by-label](https://img.shields.io/github/issues/doyensec/inql/Help%20Wanted?color=red&logo=github)](https://github.com/doyensec/inql/issues?q=is%3Aissue+is%3Aopen+label%3A%22Help+Wanted%22)
[![GitHub issues by-label](https://img.shields.io/github/issues/doyensec/inql/Good%20First%20Issue?color=f0a&logo=github)](https://github.com/doyensec/inql/issues?q=is%3Aissue+is%3Aopen+label%3A%22Good+First+Issue%22)

<img align="right" width="200" src="docs/inql.png">

## :rocket: Introduction

Welcome to InQL v5.0, a major update for our open-source GraphQL testing tool. This version provides new and improved features aimed at enhancing your GraphQL testing capabilities, making it more efficient and effective.

We appreciate your trust in InQL. Happy testing!

## :warning: Significant Updates and Breaking Changes

We've strategically revised certain aspects of InQL v5.0, leading to the deprecation of some features from v4. Notably, standalone and CLI modes, the embedded GraphiQL server, and the Timer tab are no longer available.

This streamlining allows us to focus on refining InQL's core functionality, though we recognize it may affect your established workflows. This is especially pertinent as some of these features were highlighted in the renowned [Black Hat GraphQL](https://nostarch.com/black-hat-graphql) book.

Our goal is to achieve full feature parity with v4 in the upcoming v5.1 version. In the interim, please consider using the last [v4.0.7 release](https://github.com/doyensec/inql/releases/tag/v4.0.7) or building InQL from the [v4 branch](https://github.com/doyensec/inql/tree/dev).

**:exclamation: GQLSpection - The Successor of Standalone and CLI Modes**

In order to simplify our code base, **standalone mode** and **CLI**, which allowed for InQL use outside of Burp, have been removed in InQL v5.0. These functionalities are now bundled within [GQLSpection](https://github.com/doyensec/gqlspection), a multi-use CLI tool and a Python 2/3/Jython compatible library.

GQLSpection facilitates sending introspection queries, parsing results, generating queries and mutations, and executing Points of Interest searches.

**:exclamation: Deprecation of the Timer Tab**

The *Timer* tab from InQL v4 has been discontinued in v5.0, as Burp's built-in *Logger* tool offers a more accurate and thorough alternative for visualizing query execution times. Here's a quick guide to use Burp's *Logger* instead:

- Enter the GraphQL endpoint as your search term.
- Show the *"Start response timer"* & *"End response timer"* columns.
  - **End response timer**: This denotes the time taken by the server to completely send back the response. It mirrors the data provided by the deprecated *Timer* tab but is more precise.
  - **Start response timer**: This represents the time taken by the server to process the response before starting to send it back, a crucial metric for DoS conditions.

**:exclamation: GraphiQL and Circular Relationship Detection**

Owing to time constraints, these features are temporarily absent from the v5.0 release. However, we're dedicated to reintroducing them in v5.1.

## :star2: Features

The InQL user interface is equipped with two primary components: the *Scanner* and the *Attacker*.

### :mag_right: Scanner

https://github.com/doyensec/inql/assets/105389353/77ac7f1f-1aba-415e-8566-07cefa8a5075

The *Scanner* is the core of InQL v5.0, where you can analyze a GraphQL endpoint or a local introspection schema file. It auto-generates all possible queries and mutations, organizing them into a structured view for your analysis.

**:white_check_mark: Customizable Scans**

InQL v5.0 offers the flexibility to customize your scans. Adjust the depth of generated queries or the number of spaces used for indentation. You can also perform 'Points of Interest' scans to detect potential vulnerabilities in the GraphQL schema.

**:white_check_mark: Points of Interest Analysis**

After running a Points of Interest scan, you are presented with a rich data set covering a variety of potential vulnerabilities. You can enable or disable these categories according to your needs.

**:white_check_mark: Enhanced Interactions with Burp**

InQL v5.0 seamlessly integrates with Burp, enabling you to generate queries directly from any GraphQL request in Burp. You can also send auto-generated queries to other Burp tools for further analysis.

**:white_check_mark: Custom Headers**

You have the ability to set custom headers per domain, with the domain list auto-populated from observed traffic.

### :crossed_swords: Attacker

https://github.com/doyensec/inql/assets/105389353/c7a89be3-dad8-4db6-b4a5-b8fefe043394

The *Attacker* component lets you run batch GraphQL attacks, which can be useful for circumventing poorly implemented rate limits.

### :memo: Burp's Native Message Editors

Burp's native message editors now come with an additional 'GraphQL' tab, providing an efficient way to view and modify GraphQL requests.

<img width="1209" alt="image" src="https://github.com/doyensec/inql/assets/105389353/45d2cdcd-9bfb-4ad9-b469-0126437b3e66">

# :arrow_down: Installation

To successfully install InQL v5.0, ensure you meet the following requirements:

Burp:

- Support is only provided for the most recent version of Burp.
- Compatible with both "Professional" and "Community" editions.

Java:

- The Montoya API needs Java 17 or later.

## :computer: Building the InQL extension from git

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

## :hammer_and_wrench: Setting up development environment

After building InQL as described above, you can prepare your development environment.

Begin by setting up a virtual environment with Python 2.7 for Jython compatibility. Note that necessary headers are required to build libraries with pip. For instance, using virtualenv:

```bash
$ sudo apt install -y python2.7 python2.7-dev python2-setuptools-whl python2-pip-whl python3-virtualenv libssl-dev
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

Now a bunch of tests, including isort and pylint, should run on each commit.
However, it will also change the files if necessary and cancel commit in this
case for you to inspect. So, make sure to check what's up, manually add the
changes (`git add`) and run `git commit` again (as the original commit didn't go
through).

Your environment is ready for development of InQL! Note that GQLSpection
requires its own setup. Oh, and if the GQLSpection submodule gets out of date
you'll see a message about it in `git status`. Fix it by running:

```bash
$ git submodule update
```

(this can also be done automatically when needed by modifying `~/.gitconfig`)

# :handshake: Contributing

InQL thrives on community contributions. Whether you're a developer, researcher, designer, or bug hunter, your expertise is invaluable to us. We welcome bug reports, feedback, and pull requests. Your participation helps us continue to improve InQL, making it a stronger tool for the community.

Interactions are best carried out through the Github issue tracker, but you can also reach us on social media ([@Doyensec](https://twitter.com/Doyensec)). We look forward to hearing from you!

# :busts_in_silhouette: Contributors

A special thanks to our contributors. Your dedication and commitment have been instrumental in making InQL what it is today.

Current:
- **Maintainer:** Andrew Konstantinov [@execveat (Twitter)](https://twitter.com/execveat) / [@execveat (Mastodon)](https://infosec.exchange/@execveat)
- **Contributor:** Matteo Oldani [@matteoldani (Github)](https://github.com/matteoldani)

Historical:
- **Author:** Andrea Brancaleoni [@nJoyneer (Twitter)](https://twitter.com/nJoyneer) / [thypon (Github)](https://github.com/thypon)
- List of other contributors: [AUTHORS](AUTHORS)

This project was made with support of [Doyensec](https://doyensec.com/research.html).

![Doyensec Research](docs/doyensec_logo.svg)
