// Netlify Function: history-records

exports.handler = async () => ({
  statusCode: 200,
  headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" },
  body: JSON.stringify({ records: [], total: 0, page: 1, total_pages: 1 })
});
