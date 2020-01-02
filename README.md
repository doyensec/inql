# InQL Scanner
A Burp Extension/stand-alone tool to facilitate [GraphQL](https://graphql.org/) technology security testing efforts.

![GraphQL Official Logo](docs/graphqllogo.png)

### InQL Introspection (stand-alone script)

Running `inql` from python will issue an [Introspection](https://graphql.org/learn/introspection/) query to a GraphQL
endpoint to fetch the metadata of all the:
- Queries, Mutations, Subscriptions
- their fields and arguments
- objects and custom objects types

InQL can inspect the introspection query result and generate clean documentation in different formats such as
HTML and JSON Schema.

InQL is also able to generate templates (with optional placeholders' values) for all the known types.

The resulting HTML documentation page will contain details for all available Queries, Mutations, and Subscriptions as shown here:

![Preview](docs/GraphQL_Introspection_Output.png)

Templates Generation:

![Preview](docs/Introspection_Templates.png)

Usage:
```
usage: inql [-h] [-t TARGET] [-f SCHEMA_JSON_FILE] [-k KEY] [-p PROXY]
            [--header HEADERS HEADERS] [-d] [--generate-html]
            [--generate-schema] [--generate-queries] [--insecure]
            [-o OUTPUT_DIRECTORY]

InQL Scanner

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET             Remote GraphQL Endpoint (https://<Target_IP>/graphql)
  -f SCHEMA_JSON_FILE   Schema file in JSON format
  -k KEY                API Authentication Key
  -p PROXY              IP of web proxy to go through (http://127.0.0.1:8080)
  --header HEADERS HEADERS
  -d                    Replace known GraphQL arguments types with placeholder
                        values (useful for Burp Suite)
  --generate-html       Generate HTML Documentation
  --generate-schema     Generate JSON Schema Documentation
  --generate-queries    Generate Queries
  --insecure            Accept any SSL/TLS certificate
  -o OUTPUT_DIRECTORY   Output Directory
```

Terminal Output:

![Preview](docs/Terminal_Output.png)

### Burp Suite Extension

Since v1.0 InQL was extended to also support BURP as a plugin. In that mode it will retain all the capabilities of the `inql` tool;
including a handy user interface to manipulate the queries and the documentation. Following the most important capabilities
of the UI tool:
+ search for known GraphQL paths; it will grep and match known values to detect GraphQL Technology usage in the website
+ search for exposed GraphQL development consoles; reports GraphiQL, GraphQL Playground, and common consoles
+ add a GraphQL Tab for every request/response using GraphQL Technology
+ add a GraphQL Scanner Tab inside Burp Suite; GUI for the Introspection Tool

Import the Extension in Burp:
+ Download [Jython](https://www.jython.org/downloads.html) Jar
+ Start Burp Suite
+ Extender Tab > Options > Python Enviroment > Set the location of Jython standalone JAR
+ Extender Tab > Exrtension > Add > Extension Type > Select python
+ Extension File > Set the location of `inql_burp.py` > Next
+ The output should now show the following message: `InQL Scanner Started!`

Now you should be able to find a GraphQL Scanner Tab:

![Preview](docs/inql.gif)

Usage:

+ Load a GraphQL endpoint or a JSON schema file location inside the input box
+ (Optional) Check the 'load template placeholders' checkbox; It will replace known GraphQL arguments types with placeholder values (useful to use in conjunction with the Repeater Tab)
+ Press the corresponding Button (Load URL/Load JSON)
+ After some seconds the left panel will refresh loading the directory structure for the selected endpoint
+ Selecting any query/mutation/subscription will load its template in the main text area on the right

Directory Structure will be the following:
+ url
+ - query
+  - - timestamp 1
+  - - - query1.query
+  - - - query2.query
+  - - timestamp 2
+  - - - query1.query
+  - - - query2.query
+ - mutation
+ - subscription

### Authors

*Author and Maintainer:* Andrea Brancaleoni ([@nJoyneer](https://twitter.com/nJoyneer) - [thypon](https://github.com/thypon))

*Original Author:* Paolo Stagno ([@Void_Sec](https://twitter.com/Void_Sec) - [voidsec.com](https://voidsec.com))

This project was made with love in [Doyensec Research island](https://doyensec.com/research.html).