/**
 * MCP agent client using arken-client
 *
 * Demonstrates an AI agent authenticating to an MCP server with a DID.
 * No API key. No stored credential. The agent signs each request automatically.
 *
 * Usage:
 *   node client.js
 */

'use strict';

const { createClient } = require('arken-client');

const SERVER = process.env.MCP_SERVER || 'http://localhost:4000';

async function main() {
    // Create an agent identity — generates a fresh key pair if none provided.
    // In production, persist AGENT_PRIVATE_KEY in your secrets manager.
    const agent = createClient(process.env.AGENT_PRIVATE_KEY);

    console.log(`Agent DID: ${agent.did}`);
    console.log(`Server:    ${SERVER}\n`);

    // ---------------------------------------------------------------------------
    // Call the 'time' tool
    // arken-client handles the 401 challenge-response automatically.
    // ---------------------------------------------------------------------------

    console.log('Calling /mcp/tools/time ...');
    const timeRes = await agent.fetch(`${SERVER}/mcp/tools/time`);
    const timeData = await timeRes.json();
    console.log('Response:', JSON.stringify(timeData, null, 2));

    // ---------------------------------------------------------------------------
    // Call the 'echo' tool
    // ---------------------------------------------------------------------------

    console.log('\nCalling /mcp/tools/echo ...');
    const echoRes = await agent.fetch(`${SERVER}/mcp/tools/echo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: 'hello from the agent' }),
    });
    const echoData = await echoRes.json();
    console.log('Response:', JSON.stringify(echoData, null, 2));
}

main().catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
});
