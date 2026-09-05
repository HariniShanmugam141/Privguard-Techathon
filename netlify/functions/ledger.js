// Netlify Function: ledger

exports.handler = async () => ({
  statusCode: 200,
  headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" },
  body: JSON.stringify({ blocks: [], total_blocks: 0 })
});
