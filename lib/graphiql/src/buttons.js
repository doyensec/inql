import { ToolbarButton, useEditorContext } from '@graphiql/react';

import intruderIcon from './intruder.svg';
import repeaterIcon from './repeater.svg';

const parseJSON = (variables) => {
    if (variables.trim() == "") {
        return {};
    }

    try {
        return JSON.parse(variables);
    } catch (error) {
        return {};
    }
}

const sendToButton = (tool, url, icon) => {
    return () => {
        const { queryEditor, variableEditor, headerEditor } = useEditorContext({
            nonNull: true,
        });

        const handleClick = async () => {
            const query = queryEditor.getValue();
            const variables = parseJSON(variableEditor.getValue());

            const params = new URLSearchParams(window.location.search);
            const { target, session } = Object.fromEntries(params);

            const headers = parseJSON(headerEditor.getValue());
            if (!headers.hasOwnProperty('InQL')) {
                headers['InQL'] = session;
            }

            try {
                await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        target: target,
                        query: query,
                        variables: variables,
                        headers: headers
                    })
                });
            } catch (error) {
                alert("Error sending to Repeater");
            }
        }

        const label = `Send to ${tool}`;
        return (
            <ToolbarButton label={label} onClick={handleClick}>
              <img src={icon} alt={label} height="40" width="40" />
            </ToolbarButton>
        );
    }
}

export const IntruderButton = sendToButton("Intruder", "https://inql.burp/send-to-intruder", intruderIcon);
export const RepeaterButton = sendToButton("Repeater", "https://inql.burp/send-to-repeater", repeaterIcon);
