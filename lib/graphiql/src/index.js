import React from 'react';
import { createRoot } from 'react-dom';
import { GraphiQL } from 'graphiql';
import { customFetcher, customStorage } from './custom';
import 'graphiql/graphiql.min.css';
import './index.css';

const root = createRoot(document.getElementById('root'));

// Customize GraphiQL as needed, e.g., using props and children
const customProps = {
  // Add any custom props here
};

root.render(<GraphiQL fetcher={customFetcher} storage={customStorage} {...customProps} />);
