const { getReply } = require("../lib/bot");
module.exports = function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch (_) { body = {}; } }
  const message = body && typeof body.message === "string" ? body.message.trim() : "";
  if (!message || message.length > 500) return res.status(400).json({ error: "Message must contain 1–500 characters." });
  return res.status(200).json(getReply(message));
};