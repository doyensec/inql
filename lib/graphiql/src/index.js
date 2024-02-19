import React from 'react';
import { createRoot } from 'react-dom';
import { GraphiQL } from 'graphiql';
import { explorerPlugin } from '@graphiql/plugin-explorer';
import { inql } from './inql';
import { customFetcher, customStorage } from './custom';
import 'graphiql/graphiql.min.css';
import './index.css';
import { IntruderButton, RepeaterButton } from './buttons';

console.log(inql.query);
console.log(inql.variables);
console.log(inql.target);
console.log(inql.session);

const root = createRoot(document.getElementById('root'));
root.render(
    <GraphiQL fetcher={customFetcher} storage={customStorage}
        query={inql.query}
        variables={JSON.stringify(inql.variables)}
        plugins={[explorerPlugin()]}
        toolbar={{"additionalContent": [<IntruderButton />, <RepeaterButton />]}} />
    );

