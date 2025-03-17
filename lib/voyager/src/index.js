import React from 'react';
import { createRoot } from 'react-dom';

import { Voyager, voyagerIntrospectionQuery } from 'graphql-voyager';
import 'graphql-voyager/dist/voyager.css';

const params = Object.fromEntries(new URLSearchParams(window.location.search));
const target = decodeURIComponent(params.target || "");
const session = decodeURIComponent(params.session || "");

const response = await fetch(
  target,
  {
    method: 'post',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Inql-Session': session,
    },
    body: JSON.stringify({ query: voyagerIntrospectionQuery }),
    credentials: 'omit',
  },
);
const introspection = await response.json();

const root = createRoot(document.getElementById('root'));
root.render(<Voyager introspection={introspection} />);
