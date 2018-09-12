#!/usr/bin/python

# Title:	GraphQL Introspection
# A small tool to query a GraphQL endpoint with introspection in order to retrieve the documentation of all the queries & mutations
# Author:	Paolo Stagno (@Void_Sec)
# Version:	1.1

import requests
import os
import argparse
import sys

stl = """
			<style>
				body {
					font-family: Roboto;
					background-color: #f9f9f9;
				}
				li.query {
					color: #368cbf;
				}
				li.mutation {
					color: #30a;
				}
				li.argument {
					color: #edae49;
				}
				li.type {
					color: #7ebc59;
				}
				li.deprecated {
					color: red;
					text-decoration: underline wavy red;
				}
				li.field {
				}
				li.description {
					color: grey;
				}
				div.box {
					background-color: white;
					width: 300px;
					border: 5px solid grey;
					padding: 10px;
					margin: 10px;
				}
			</style>
			"""

def query(target,key):
	#Introspection Query
	#-----------------------
	query = "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"
	old_query = "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description args{...InputValue}onOperation onFragment onField}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"
	#-----------------------
	if key:
		headers = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"
			"Authorization": key
		}
	else:
		headers = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"
		}
	try:
		request = requests.post(target, json={"query": query}, headers=headers)
		if request.status_code == 200:
			return request.json()
		else:
			print "Trying the old ntrospection query"
			request = requests.post(target, json={"query": old_query}, headers=headers)
			if request.status_code == 200:
				return request.json()
			else:
				print "Query failed! Code {}".format(request.status_code)
				sys.exit(1)
	except requests.exceptions.MissingSchema:
		print "Missing http:// or https:// schema from Target URL"
		sys.exit(1)

def main():
	parser = argparse.ArgumentParser(prog="GraphQL_Introspection.py", description="GraphQL Introspection")
	parser.add_argument("-t", required=True, dest="target", help="Remote GraphQL Endpoint (http/s://<Target_IP>)")
	parser.add_argument("-k", dest="key", help="API Authentication Key")
	parser.add_argument("-o", "--output", required=True, help="Directs the output to a file your choice")
	args = parser.parse_args()

	if args.target and args.output:
		CustomQuery="None"
		CustomMutation="None"
		with open(args.output, 'w') as output_file:
			result = query(args.target,args.key)
			output_file.write("<html><head><title>GraphQL Schema</title>")
			output_file.write(stl)
			output_file.write("</head><body><h2>GraphQL Schema</h2><h3><a href='{0}'>{0}</a></h3>".format(args.target))
			output_file.write("<div class='box'><h4>Legend</h4><ul><li class='query'>Queries</li><li class='mutation'>Mutations</li><li class='argument'>Arguments</li><li class='type'>Types: String, Float, !not_null, [list]</li><li class='deprecated'>Deprecated</li><li class='field'>Fields</li></ul></div>")
			output_file.write("<p>Available Operations Types:</p>")
			
			#TODO: check if key exist in dict/list before accessing them
			try:
				#Query & Mutations
				if 'mutationType' in result['data']['__schema'] and result['data']['__schema']['mutationType'] is not None:
					output_file.write("<ul><li class='mutation'>{0}</li>\n".format(result['data']['__schema']['mutationType']['name']))
					if result['data']['__schema']['mutationType']['name'] != "Mutation":
						CustomMutation = result['data']['__schema']['mutationType']['name']

				if result['data']['__schema']['queryType']['name'] is not None:
					output_file.write("<li class='query'>{0}</li></ul>\n".format(result['data']['__schema']['queryType']['name']))
					if result['data']['__schema']['queryType']['name'] != "Query":
						CustomQuery = result['data']['__schema']['queryType']['name']

				i=0
				output_file.write("<br>")
				if result['data']['__schema']['types'] is not None:
					rt = result['data']['__schema']['types']
					output_file.write("<ul>\n")
					for types in rt:
						j=0
						#Data -> Shema -> Types (kind, name)
						if rt[i]['kind'] is not None and rt[i]['kind'] != "INPUT_OBJECT" and rt[i]['name'] not in ["__Schema", "__Type", "__TypeKind", "__Field", "__InputValue", "__EnumValue", "__Directive", "__DirectiveLocation"]:

							if rt[i]['kind'] != "SCALAR":
								output_file.write("<li>{0}</li>\n".format(rt[i]['kind']))

							if rt[i]['name'] is not None and rt[i]['kind'] != "SCALAR":
								#TODO different mutations or query schema like ex. Calc								
								if rt[i]['name'] == "Mutation":
									output_file.write("<li class='mutation'>{0}</li>\n".format(rt[i]['name']))

								elif rt[i]['name'] == "Query":
									output_file.write("<li class='query'>{0}</li>\n".format(rt[i]['name']))
								#elif result['data']['__schema']['types'][i]['name'] == CustomMutation:
									#output_file.write("<li class='mutation'>{0}</li>\n".format(CustomMutation)
								#elif result['data']['__schema']['types'][i]['name'] == CustomQuery:
									#output_file.write("<li class='query'>{0}</li>\n".format(CustomQuery)
								else:
									output_file.write("<li class='type'>{0}</li>\n".format(rt[i]['name']))
						else:
							continue
						k=0	
						if rt[i]['kind'] == "ENUM" and rt[i]['enumValues'] is not None:	
							output_file.write("<ul>\n")
							for enumValues in rt[i]['enumValues']:
								if rt[i]['enumValues'][k]['name'] is not None:
									output_file.write("<li>{0}</li>\n".format(rt[i]['enumValues'][k]['name']))
								
								if rt[i]['enumValues'][k]['description'] is not None:
									output_file.write("<ul><li class='description'>{0}</li></ul>\n".format(rt[i]['enumValues'][k]['description']))
								
								if rt[i]['enumValues'][k]['isDeprecated'] is not False and rt[i]['enumValues'][k]['isDeprecated'] is not None:
									output_file.write("<ul><li class='deprecated'>Is Deprecated</li></ul>\n")
								
								if rt[i]['enumValues'][k]['deprecationReason'] is not None:
									output_file.write("<ul><li>Reason: {0}</li></ul>\n".format(rt[i]['enumValues'][k]['deprecationReason']))
								k=k+1
							output_file.write("</ul><br>")
						
						if rt[i]['fields'] is not None:
							output_file.write("<ul>")
							#Data -> Shema -> Types -> Fields (name, isDeprecated, deprecationReason, description)
							for fields in result['data']['__schema']['types'][i]['fields']:
								if rt[i]['fields'][j]['name'] is not None:
									#TODO different mutations or query schema like Calc
									if rt[i]['name'] == "Query":
										output_file.write("<li class='query'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
									elif rt[i]['name'] == "Mutation":
										output_file.write("<li class='mutation'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
									elif rt[i]['kind'] == "OBJECT":
										output_file.write("<li class='field'>{0}</li>\n".format(rt[i]['fields'][j]['name']))
									else:
										output_file.write("<li>{0}</li>\n".format(rt[i]['fields'][j]['name']))
								
								if rt[i]['fields'][j]['isDeprecated'] is not False and rt[i]['fields'][j]['isDeprecated'] is not None:
									output_file.write("<li class='deprecated'>Is Deprecated</li>\n")
								
								if rt[i]['fields'][j]['deprecationReason'] is not None:
									output_file.write("<li>Reason: {0}</li>\n".format(rt[i]['fields'][j]['deprecationReason']))
								
								if rt[i]['fields'][j]['description'] is not None and rt[i]['fields'][j]['description'] != '': 
									output_file.write("<li class='description'>{0}</li>\n".format(rt[i]['fields'][j]['description']))
								
								if rt[i]['fields'][j]['type'] is not None:
									if rt[i]['fields'][j]['type']['name'] is not None:
										output_file.write("<ul><li class='type'>{0}</li></ul>\n".format(rt[i]['fields'][j]['type']['name']))
								
								if rt[i]['fields'][j]['type']['ofType'] is not None and rt[i]['fields'][j]['type']['ofType']['name'] is not None:
									if rt[i]['fields'][j]['type']['kind'] is not None and rt[i]['fields'][j]['type']['kind'] == "LIST":
										output_file.write("<ul><li class='type'>[{0}]</li></ul>\n".format(rt[i]['fields'][j]['type']['ofType']['name']))									
									
									elif rt[i]['fields'][j]['type']['kind'] is not None and rt[i]['fields'][j]['type']['kind'] == "NON_NULL":
										output_file.write("<ul><li class='type'>!{0}</li></ul>\n".format(rt[i]['fields'][j]['type']['ofType']['name']))
									
									else:	
										output_file.write("<ul><li class='type'>{0}</li></ul>\n".format(rt[i]['fields'][j]['type']['ofType']['name']))
								x=0
								if rt[i]['fields'][j]['args'] is not None:
									output_file.write("<ul>\n")
									#Data -> Shema -> Types -> Fields -> Args (defaultValue, name, description)
									for args in rt[i]['fields'][j]['args']:
										if rt[i]['fields'][j]['args'][x]['defaultValue'] is not None:
											output_file.write("<li>{0}</li>\n".format(rt[i]['fields'][j]['args'][x]['defaultValue']))
										
										if rt[i]['fields'][j]['args'][x]['name'] is not None:
											output_file.write("<li class='argument'>{0}</li>\n".format(rt[i]['fields'][j]['args'][x]['name']))
										
										if rt[i]['fields'][j]['args'][x]['description'] is not None and rt[i]['fields'][j]['args'][x]['description'] != '':
											output_file.write("<li class='description'>{0}</li>\n".format(rt[i]['fields'][j]['args'][x]['description']))
										
										#Data -> Shema -> Types -> Fields -> Args -> Type (name, ofType, kind)
										if rt[i]['fields'][j]['args'][x]['type'] is not None:
											output_file.write("<ul>")
											if rt[i]['fields'][j]['args'][x]['type']['kind'] == "LIST":
												output_file.write("<li class='type'>[{0}]</li>\n".format(rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
											
											elif rt[i]['fields'][j]['args'][x]['type']['kind'] == "NON_NULL":
												output_file.write("<li class='type'>!{0}</li>\n".format(rt[i]['fields'][j]['args'][x]['type']['ofType']['name']))
											
											else:	
												if rt[i]['fields'][j]['args'][x]['type']['name'] is not None:
													output_file.write("<li class='type'>{0}</li>\n".format(rt[i]['fields'][j]['args'][x]['type']['name']))
												
												if rt[i]['fields'][j]['args'][x]['type']['ofType'] is not None:
													output_file.write("<li>{0}</li>\n".format(rt[i]['fields'][j]['args'][x]['type']['ofType']))
												
											output_file.write("</ul>\n")
										x=x+1
									output_file.write("</ul><br>\n")
								j=j+1
							output_file.write("</ul><br>\n")
						i=i+1
					output_file.write("</ul>\n")
			#except KeyError: 
			except Exception:
				raise
			output_file.write("</body></html>")
			output_file.close()
			sys.exit(0)
	else:
		print "Missing Arguments"
		parser.print_help()

if __name__ == "__main__":
	try:
		main()
	except (KeyboardInterrupt):
		print "Quitting..."
		sys.exit(0)
