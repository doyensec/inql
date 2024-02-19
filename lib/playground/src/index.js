import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'react-redux';
import { Playground, store } from 'graphql-playground-react';

const params = Object.fromEntries(new URLSearchParams(window.location.search));
const target = decodeURIComponent(params.target || "");
const session = decodeURIComponent(params.session || "");

const headers = {
  "X-Inql-Session": session,
};

ReactDOM.render(
  <Provider store={store}>
    <Playground endpoint={target} headers={headers} />
  </Provider>,
  document.getElementById('root')
);
