![GraphQL Official Logo](Misc/graphqllogo.png)

# GraphQL Security Toolkit
With the increasing popularity of [GraphQL](https://graphql.org/) technology, we will be using this repository to publish scripts and other resources that can facilitate security testing efforts.

## GraphQL Introspection
*Author:* Paolo Stagno ([@Void_Sec](https://twitter.com/Void_Sec)) 

A tool to query a GraphQL endpoint with introspection in order to retrieve the documentation of all the Queries, Mutations & Subscriptions.
The script will also generate templates (with optional placeholders) for all the known types, usefull for Burp Suite repeater.

The resulting HTML page will contain details for all available Queries, Mutations and Subscriptions as shown here:

![Preview](Introspection/GraphQL_Introspection_Output.png)

Usage:
```
GraphQL_Introspection.py [-h] [-t TARGET] [-f SCHEMA_JSON_FILE]
                                [-k KEY] [-p PROXY] [-d] [-c]

optional arguments:
  -h, --help           show this help message and exit
  -t TARGET            Remote GraphQL Endpoint (https://<Target_IP>/graphql)
  -f SCHEMA_JSON_FILE  Schema file in JSON format
  -k KEY               API Authentication Key
  -p PROXY             IP of web proxy to go through (http://127.0.0.1:8080)
  -d                   Replace known GraphQL arguments types with placeholder
                       values (useful for Burp Suite repeater)
  -c                   Add custom objects to the documentation output (verbose)
  
$python GraphQL_Introspection.py -t http://192.168.1.82/examples/04-bank/graphql
```
### Future Updates

We are currenyly working on "porting" this script into a Burp Extension with a nice and clean GUI.
Do not be afraid, it will also be possible to use it as a stand-alone script.
