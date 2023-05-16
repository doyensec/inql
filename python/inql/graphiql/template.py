# coding: utf-8
from string import Template


def graphiql_template(address, burp):
    burp_integration = """
    (function() {
      var toolbar = document.querySelector('.graphiql-toolbar');
      toolbar.insertAdjacentHTML('beforeend', `
        <style>
          #send-to-repeater {
            position: relative;
            display: inline-block;
          }

          #send-help {
          visibility: hidden;
          width: 140px;
          background-color: white;
          color: #444;
          text-align: center;
          padding: 2px;
          border-radius: 4px;

          position: absolute;
          top: 100%;
          z-index: 100;
        }

        /* Show the tooltip text when you mouse over the tooltip container */
        #send-to-repeater:hover #send-help {
          visibility: visible;
        }

        #send-confirmation, #send-error {
          color: white;
          padding: 4px 8px;
          border-radius: 4px;

          visibility: hidden;
          position: fixed;
          top: 1.5em;
          z-index: 100;
        }

        #send-confirmation {
          background-color: green;
        }

        #send-error {
          background-color: red;
        }

        #send-confirmation.shown, #send-error.shown {
          visibility: visible;
          animation: fadeIn 1s;
        }

        #send-confirmation.hidden, #send-error.hidden {
          visibility: hidden;
          animation: fadeOut 1s;
        }

        @keyframes fadeIn {
          from {opacity: 0;}
          to {opacity: 1;}
        }

        @keyframes fadeOut {
          from {opacity: 1; visibility: visible;}
          to {opacity: 0; visibility: hidden;}
        }
        </style>
        <button id="send-to-repeater" type="button" class="graphiql-un-styled graphiql-toolbar-button" aria-label="Send to Repeater" data-state="tooltip-hidden" data-reach-tooltip-trigger="">
          <span id="send-help">Send to Repeater</span>
          <span id="send-confirmation">Query sent to Repeater!</span>
          <span id="send-error">Couldn't send query to Repeater :(</span>
          <svg viewBox="-10 -10 75 75" xmlns="http://www.w3.org/2000/svg" fill="#ff6632"><path d="M 8 4 C 5.792969 4 4 5.792969 4 8 L 4 42 C 4 44.207031 5.792969 46 8 46 L 24 46 L 24 38.585938 L 32.585938 30 L 24 30 L 24 21 L 12.585938 21 L 24 9.585938 L 24 4 Z M 26 4 L 26 10.414063 L 17.414063 19 L 26 19 L 26 28 L 37.414063 28 L 26 39.414063 L 26 46 L 42 46 C 44.207031 46 46 44.207031 46 42 L 46 8 C 46 5.792969 44.207031 4 42 4 Z"></path></svg>
        </button>`)
      var sendToRepeater = document.getElementById('send-to-repeater');
      var sendConfirmation = document.getElementById('send-confirmation');
      var sendError = document.getElementById('send-error');

      sendToRepeater.onclick = function() {
        // Sanitize params
        var params = JSON.parse(JSON.stringify(parameters));

        // Sanitize variables, if present
        if ('variables' in params) {
          try {
              params['variables'] = JSON.parse(params['variables']);
          } catch (e) {
              console.log('Cannot parse variables (not sent to repeater)');
          }
        }

        fetch(address, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(params)
        })
        .then((result) => {
          // Success
          sendConfirmation.classList.remove('hidden');
          sendConfirmation.classList.add('shown');

          setTimeout(() => {
            sendConfirmation.classList.remove('shown');
            sendConfirmation.classList.add('hidden');
          }, 3000);
        })
        .catch((error) => {
          // Error
          sendError.classList.remove('hidden');
          sendError.classList.add('shown');

          console.log(error);

          setTimeout(() => {
            sendError.classList.remove('shown');
            sendError.classList.add('hidden');
          }, 3000);
        })
      }
      toolbar.appendChild(sendToRepeater);
    } ());
    """

    html = Template("""
<!--
 *  Copyright (c) 2021 GraphQL Contributors
 *  All rights reserved.
 *
 *  This source code is licensed under the license found in the
 *  LICENSE file in the root directory of this source tree.
-->
<!DOCTYPE html>
<html>
  <head>
    <style>
      body {
        height: 100%;
        margin: 0;
        width: 100%;
        overflow: hidden;
      }

      #graphiql {
        height: 100vh;
      }
    </style>

    <!--
      This GraphiQL example depends on Promise and fetch, which are available in
      modern browsers, but can be "polyfilled" for older browsers.
      GraphiQL itself depends on React DOM.
      If you do not want to rely on a CDN, you can host these files locally or
      include them directly in your favored resource bundler.
    -->
    <script
      crossorigin
      src="https://unpkg.com/react@17/umd/react.development.js"
    ></script>
    <script
      crossorigin
      src="https://unpkg.com/react-dom@17/umd/react-dom.development.js"
    ></script>

    <!--
      These two files can be found in the npm module, however you may wish to
      copy them directly into your environment, or perhaps include them in your
      favored resource bundler.
     -->
    <link rel="stylesheet" href="https://unpkg.com/graphiql/graphiql.min.css" />
  </head>

  <body>
    <div id="graphiql">Loading...</div>
    <script
      src="https://unpkg.com/graphiql/graphiql.min.js"
      type="application/javascript"
    ></script>
    <script>
    // Parse the search string to get url parameters.
    //var address = "http://localhost:60450/https://api.spacex.land:443/graphql?query=query%20%7B%0A%09capsulesPast%28offset%3A1334%2C%20sort%3A%22code%2A%22%2C%20find%3A%7Btype%3A%20%22code%2A%22%2C%20original_launch%3A%20Date%2C%20mission%3A%20%22code%2A%22%2C%20id%3A%2014%2C%20reuse_count%3A%201334%2C%20landings%3A%201334%2C%20status%3A%20%22code%2A%22%7D%2C%20limit%3A1334%2C%20order%3A%22code%2A%22%29%20%7B%0A%09%09dragon%20%7B%0A%09%09%09launch_payload_mass%20%7B%0A%09%09%09%09lb%0A%09%09%09%7D%0A%09%09%7D%0A%09%09type%0A%09%09original_launch%0A%09%09missions%20%7B%0A%09%09%09flight%0A%09%09%7D%0A%09%09id%0A%09%09reuse_count%0A%09%09landings%0A%09%09status%0A%09%7D%0A%7D";
    var address = "${ADDRESS}"
    var search = window.location.search;
    //search = "?query=query%20%7B%0A%09capsulesPast%28offset%3A1334%2C%20sort%3A%22code%2A%22%2C%20find%3A%7Btype%3A%20%22code%2A%22%2C%20original_launch%3A%20Date%2C%20mission%3A%20%22code%2A%22%2C%20id%3A%2014%2C%20reuse_count%3A%201334%2C%20landings%3A%201334%2C%20status%3A%20%22code%2A%22%7D%2C%20limit%3A1334%2C%20order%3A%22code%2A%22%29%20%7B%0A%09%09dragon%20%7B%0A%09%09%09launch_payload_mass%20%7B%0A%09%09%09%09lb%0A%09%09%09%7D%0A%09%09%7D%0A%09%09type%0A%09%09original_launch%0A%09%09missions%20%7B%0A%09%09%09flight%0A%09%09%7D%0A%09%09id%0A%09%09reuse_count%0A%09%09landings%0A%09%09status%0A%09%7D%0A%7D";

    // Populate parameters from the URI
    var parameters = {};
    search.substr(1).split('&').forEach(function (entry) {
      var eq = entry.indexOf('=');
      if (eq >= 0) {
        parameters[decodeURIComponent(entry.slice(0, eq))] =
        decodeURIComponent(entry.slice(eq + 1));
      }
    });

    // When the query and variables string is edited, update the URL bar so
    // that it can be easily shared
    function onEditQuery(newQuery) {
      parameters.query = newQuery;
      updateURL();
    }

    function onEditVariables(newVariables) {
      parameters.variables = newVariables;
      updateURL();
    }

    function onEditOperationName(newOperationName) {
      parameters.operationName = newOperationName;
      updateURL();
    }

    function updateURL() {
      var newSearch = '?' + Object.keys(parameters).filter(function (key) {
        return Boolean(parameters[key]);
      }).map(function (key) {
      return encodeURIComponent(key) + '=' +
      encodeURIComponent(parameters[key]);
      }).join('&');
      history.replaceState(null, null, newSearch);
    }

    const graphQLFetcher = (graphQLParams) =>
      fetch(address, {
        method: 'post',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(graphQLParams),
      })
    .then(response => response.json())
    .catch((response) => response);

    ReactDOM.render(
      React.createElement(GraphiQL, {
        fetcher: graphQLFetcher,
        // pre-load query from URI
        query: parameters.query,
        variables: parameters.variables,
        operationName: parameters.operationName,
        onEditQuery: onEditQuery,
        onEditVariables: onEditVariables,
        onEditOperationName: onEditOperationName
      }),
      document.getElementById('graphiql'),
    );

    // Branding
    document.querySelector('.graphiql-logo').innerHTML = '<a href="https://github.com/doyensec/inql"><img src="https://github.com/doyensec/inql/blob/master/docs/inql.png?raw=true" style="display: block; height:6em; z-index: 10; position: relative"></img></a>';

    ${BURP_INTEGRATION}
    </script>
  </body>
</html>
""").substitute(ADDRESS=address, BURP_INTEGRATION=burp_integration if burp else "")

    return html
