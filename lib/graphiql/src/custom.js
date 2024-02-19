import { inql } from './inql';

import { createGraphiQLFetcher, createLocalStorage } from '@graphiql/toolkit';
import md5 from 'md5';

/*
  Custom `fetcher` and `storage` implementations for GraphiQL. Allows having
  multiple GraphiQL instances with different history & tabs hosted on the same
  domain.
*/

const serverHash = md5(inql.target).substring(20);
localStorage.setItem(`server-${serverHash}:graphiql:server`, inql.target);

const customFetcher = createGraphiQLFetcher({
    url: inql.target,
    headers: {
      "X-Inql-Session": inql.session,
    },
  });
  
const customStorage = createLocalStorage({namespace: `${inql.session}-${serverHash}`});

export {
  customFetcher,
  customStorage
}