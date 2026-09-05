// Netlify Function: sanitize-document-stub
// Document upload (PDF/image redaction) requires Python + OCR and cannot run on Netlify.
// This stub returns a friendly message so the UI handles it gracefully.

exports.handler = async () => ({
  statusCode: 200,
  headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" },
  body: JSON.stringify({
    status: "unavailable",
    message: "Document upload redaction requires the local Python server. Please use the Enter Text tab for live redaction on this hosted version."
  })
});
