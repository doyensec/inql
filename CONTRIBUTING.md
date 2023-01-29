# Welcome to InQL contributing guide

Thank you for investing your time in contributing to InQL!

In this guide you will get an overview of our project and contribution workflow we expect.

## Project history and current status

Originally InQL extension was implemented in Jython as it was officially supported by Portswigger. However, since then Jython development has stalled with Jython 3 version being abandoned by the development team. In the meantime, Python 2 has reached end of life in 2020 which lead to more and more tooling dropping support for it. Although technically it is possible to run Python 3 in JVM through [GraalVM](https://www.graalvm.org/python/) and [JEP](https://github.com/ninia/jep) none of these are supported by Portswigger and as such our users would need to deal with complicated setup before running InQL, which would hurt adoption.

Due to these considerations, we've decided to rewrite InQL in Kotlin. Current development is happening in [dev](https://github.com/doyensec/inql/tree/dev) branch and all of the commits & pull request should be sent to this branch.

Right now the goal for the next version is refactoring the GraphQL parsing functionality in a separate (Jython / Python 2.7 / Python 3+ compatible) library, [GQLSpection](https://github.com/doyensec/gqlspection). Isolating this code will allow us to focus on improving and stabilizing this library (in Python) and rewriting everything else in Kotlin. Once GQLSpection becomes the last Python dependency, we will rewrite it in Kotlin as well (original repo will become a standalone tool, allowing it to drop support for Jython and Python 2.7).

## Where to send patches

First, decide which repo to target. If you are interested in GraphQL introspection parsing code, please target [GQLSpection](https://github.com/doyensec/gqlspection), if you are interested in GUI and Burp-specific features instead then go ahead and target InQL proper.

In both repos development is happening in **dev** branches, so this is where you should be sending pull requests (not the default **main** branches, as they only contain released code).

## Development workflow

1. Fork the repository
2. Check out the 'dev' branch
3. Compile the existing code by running `./gradlew` or `./gradlew.bat`
4. Make changes in your fork
5. Create pull request to the 'dev' branch, explain the rationale in the message or link to an issue that is solved by PR
