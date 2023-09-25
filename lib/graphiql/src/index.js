import React from 'react';
import { createRoot } from 'react-dom';
import { GraphiQL } from 'graphiql';
import { explorerPlugin } from '@graphiql/plugin-explorer';
import { customFetcher, customStorage } from './custom';
import 'graphiql/graphiql.min.css';
import './index.css';

import { IntruderButton, RepeaterButton } from './buttons';

const root = createRoot(document.getElementById('root'));

root.render(
    <GraphiQL fetcher={customFetcher} storage={customStorage}
        plugins={[explorerPlugin()]}
        toolbar={{"additionalContent": [<IntruderButton />, <RepeaterButton />]}} />
    );

