// Netlify Function: history-stats
// Returns mock stats for the dashboard

exports.handler = async () => ({
  statusCode: 200,
  headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" },
  body: JSON.stringify({
    total_documents: 0,
    sanitized_documents: 0,
    viewed_documents: 0,
    deleted_documents: 0,
    success_rate: 100,
    viewed_this_month: 0,
    deleted_this_month: 0
  })
});
