const { getReply, MENU } = require("../lib/bot");
const API = "https://api.telegram.org";
async function telegram(method, payload) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) throw new Error("TELEGRAM_BOT_TOKEN is not configured");
  const response = await fetch(API + "/bot" + token + "/" + method, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
  if (!response.ok) throw new Error("Telegram API returned " + response.status);
  return response.json();
}
module.exports = async function handler(req, res) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).send("Method not allowed"); }
  const secret = process.env.TELEGRAM_WEBHOOK_SECRET;
  if (!secret || req.headers["x-telegram-bot-api-secret-token"] !== secret) return res.status(401).send("Unauthorized");
  let update = req.body;
  if (typeof update === "string") { try { update = JSON.parse(update); } catch (_) { update = null; } }
  const message = update && (update.message || update.edited_message);
  if (!message || !message.chat || !message.chat.id || typeof message.text !== "string") return res.status(200).json({ ok: true });
  const reply = getReply(message.text);
  const keyboard = MENU.map(item => [{ text: item.label }]);
  try {
    const links = reply.links.length ? "\n\n" + reply.links.map(link => link.label + ": " + (link.url.startsWith("/") ? "https://nexus-q.link" + link.url : link.url)).join("\n") : "";
    await telegram("sendMessage", { chat_id: message.chat.id, text: reply.text + links, reply_markup: { keyboard, resize_keyboard: true, is_persistent: true } });
    return res.status(200).json({ ok: true });
  } catch (error) { console.error("Telegram webhook delivery failed:", error.message); return res.status(500).json({ ok: false }); }
};