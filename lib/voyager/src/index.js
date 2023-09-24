import React from 'react';
import { createRoot } from 'react-dom';

import { Voyager, voyagerIntrospectionQuery } from 'graphql-voyager';
import 'graphql-voyager/dist/voyager.css';

const params = new URLSearchParams(window.location.search);
const { server, session } = Object.fromEntries(params);


const response = await fetch(
  server,
  {
    method: 'post',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      InQL: session,
    },
    body: JSON.stringify({ query: voyagerIntrospectionQuery }),
    credentials: 'omit',
  },
);
const introspection = await response.json();

const root = createRoot(document.getElementById('root'));
root.render(<Voyager introspection={introspection} />);
