// Netlify Function: profiles

exports.handler = async () => ({
  statusCode: 200,
  headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" },
  body: JSON.stringify({
    profiles: ["HIPAA", "GDPR", "PCI-DSS", "CUSTOM"],
    active_profile: "HIPAA"
  })
});
