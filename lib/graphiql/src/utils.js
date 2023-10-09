const params = new URLSearchParams(window.location.search);
const {
    server: encodedServer,
    session: encodedSesssion,
    query: encodedQuery,
    variables: encodedVariables } = Object.fromEntries(params);

const server = decodeURIComponent(encodedServer);
const session = decodeURIComponent(encodedSesssion);
const query = decodeURIComponent(encodedQuery);
const variables = decodeURIComponent(encodedVariables);

export {
    server,
    session,
    query,
    variables
};
