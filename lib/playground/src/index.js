import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'react-redux';
import { Playground, store } from 'graphql-playground-react';

const params = new URLSearchParams(window.location.search);
const { server, session } = Object.fromEntries(params);

const headers = {
  InQL: session,
};

ReactDOM.render(
  <Provider store={store}>
    <Playground endpoint={server} headers={headers} />
  </Provider>,
  document.getElementById('root')
);
