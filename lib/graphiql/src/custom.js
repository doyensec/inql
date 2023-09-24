import { createGraphiQLFetcher, createLocalStorage } from '@graphiql/toolkit';
import md5 from 'md5';

/*
  Custom `fetcher` and `storage` implementations for GraphiQL. Allows having
  multiple GraphiQL instances with different history & tabs hosted on the same
  domain.
*/

const params = new URLSearchParams(window.location.search);
const { server, session } = Object.fromEntries(params);

const serverHash = md5(server).substring(20);
localStorage.setItem(`server-${serverHash}:graphiql:server`, server);

export const customFetcher = createGraphiQLFetcher({
  url: server,
  headers: {
    InQL: session,
  },
});

export const customStorage = createLocalStorage({namespace: `${session}-${serverHash}`});
