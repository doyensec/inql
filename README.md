# InQL Scanner
A security testing tool to facilitate [GraphQL](https://graphql.org/) technology security auditing efforts.

![GraphQL Official Logo](docs/graphqllogo.png)

InQL can be used as a stand-alone script, or as a [Burp Suite](https://portswigger.net/burp) extension.

## InQL Stand-Alone

Running `inql` from Python will issue an [Introspection](https://graphql.org/learn/introspection/) query to the target GraphQL endpoint in order fetch metadata information for:

- Queries, mutations, subscriptions
- Its fields and arguments
- Objects and custom objects types

InQL can inspect the introspection query results and generate clean documentation in different formats, such as
HTML and JSON schema. InQL is also able to generate templates (with optional placeholders) for all the known data types.

The resulting HTML documentation page will contain details for all available `Queries`, `Mutations`, and `Subscriptions` as shown here:

![Preview](docs/GraphQL_Introspection_Output.png)

The following screenshot shows the use of templates generation:

![Preview](docs/Introspection_Templates.png)

For all supported options, check the command line help:
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

## InQL Burp Suite Extension

Since version 1.0 of the tool, InQL was extended to operate within Burp Suite. In this mode, the tool will retain all the capabilities of the stand-alone script plus a handy user interface to manipulate queries. 

Using the `inql` extension for Burp Suite, you can:

+ Search for known GraphQL URL paths; the tool will grep and match known values to detect GraphQL endpoints within the target website
+ Search for exposed GraphQL development consoles (*GraphiQL*, *GraphQL Playground*, and other common consoles)
+ Use a custom GraphQL tab displayed on each HTTP request/response containing GraphQL
+ Leverage the templates generation by sending those requests to Burp's Repeater tool
+ Configure the tool by using a custom settings tab

![Preview](docs/inql.gif)

To use `inql` in Burp Suite, import the Python extension:

+ Download [Jython](https://www.jython.org/downloads.html) Jar
+ Start Burp Suite
+ Extender Tab > Options > Python Enviroment > Set the location of Jython standalone JAR
+ Extender Tab > Extension > Add > Extension Type > Select python
+ Extension File > Set the location of `inql_burp.py` > Next
+ The output should now show the following message: `InQL Scanner Started!`

*In future, we might consider integrating the extension within Burp's BApp Store.*

### Burp Extension Usage

Getting started with `inql` Burp extension is easy:

1. Load a GraphQL endpoint or a JSON schema file location inside the top input box
2. *(Optional)* Check the 'load template placeholders' checkbox; This will replace known GraphQL arguments types with placeholder values (useful to use in conjunction with the Repeater Tab)
3. Press the corresponding button (*Load URL* or *Load JSON*)
4. After few seconds, the left panel will refresh loading the directory structure for the selected endpoint
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
5.  Selecting any *query*/*mutation*/*subscription* will load the corresponding template in the main text area

## Credits

*Author and Maintainer:* Andrea Brancaleoni ([@nJoyneer](https://twitter.com/nJoyneer) - [thypon](https://github.com/thypon))
*Original Author:* Paolo Stagno ([@Void_Sec](https://twitter.com/Void_Sec) - [voidsec.com](https://voidsec.com))

This project was made with love in [Doyensec Research island](https://doyensec.com/research.html).
