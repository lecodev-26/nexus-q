(function () {
  if (window.__nqBotWidgetLoaded) return;
  window.__nqBotWidgetLoaded = true;

  var mascot = "/nexusqbot.png";
  var launcher = document.createElement("button");
  launcher.id = "nq-bot-launcher";
  launcher.type = "button";
  launcher.setAttribute("aria-label", "Open NEXUS-Q assistant");
  launcher.setAttribute("aria-expanded", "false");
  launcher.innerHTML = '<img src="' + mascot + '" alt="" aria-hidden="true">';

  var panel = document.createElement("section");
  panel.id = "nq-bot-panel";
  panel.setAttribute("aria-label", "NEXUS-Q project assistant");
  panel.setAttribute("aria-hidden", "true");
  panel.innerHTML = '<div class="nq-bot-head"><div class="nq-bot-identity"><img class="nq-bot-avatar" src="' + mascot + '" alt="" aria-hidden="true"><div><div class="nq-bot-brand">NEXUS-Q ASSISTANT</div><span class="nq-bot-status">Your guide to the NEXUS-Q ecosystem</span></div></div><button type="button" id="nq-bot-close" aria-label="Close chat">×</button></div><div class="nq-bot-messages" id="nq-bot-messages" aria-live="polite"></div><div class="nq-bot-topics" id="nq-bot-topics"></div><form class="nq-bot-form" id="nq-bot-form"><input id="nq-bot-input" maxlength="500" autocomplete="off" placeholder="Ask about NEXUS-Q…" aria-label="Your question"><button id="nq-bot-send" type="submit">Send</button></form><div class="nq-bot-foot">NEXUS-Q project guidance · <a href="/privacy">Privacy information</a></div>';

  document.body.appendChild(launcher);
  document.body.appendChild(panel);

  var messages = panel.querySelector("#nq-bot-messages");
  var topics = panel.querySelector("#nq-bot-topics");
  var form = panel.querySelector("#nq-bot-form");
  var input = panel.querySelector("#nq-bot-input");
  var send = panel.querySelector("#nq-bot-send");
  var busy = false;
  var typing = null;
  var labels = ["What is NEXUS-Q?", "Post-Quantum Cryptography", "SDK & tools", "Installation", "Documentation", "Contact"];

  function open() {
    panel.setAttribute("aria-hidden", "false");
    launcher.setAttribute("aria-expanded", "true");
    input.focus();
  }

  function close() {
    panel.setAttribute("aria-hidden", "true");
    launcher.setAttribute("aria-expanded", "false");
    launcher.focus();
  }

  function addMessage(text, who, links) {
    var bubble = document.createElement("div");
    bubble.className = "nq-bot-msg" + (who === "user" ? " user" : "");
    bubble.textContent = text;
    if (links && links.length) {
      var list = document.createElement("div");
      list.className = "nq-bot-links";
      links.forEach(function (link) {
        var a = document.createElement("a");
        a.textContent = link.label;
        a.href = link.url;
        if (/^https?:/.test(link.url)) {
          a.target = "_blank";
          a.rel = "noopener noreferrer";
        }
        list.appendChild(a);
      });
      bubble.appendChild(list);
    }
    messages.appendChild(bubble);
    messages.scrollTop = messages.scrollHeight;
  }

  function showTyping() {
    typing = document.createElement("div");
    typing.className = "nq-bot-typing";
    typing.setAttribute("role", "status");
    typing.setAttribute("aria-label", "NEXUS-Q assistant is preparing a response");
    typing.innerHTML = "<span></span><span></span><span></span>";
    messages.appendChild(typing);
    messages.scrollTop = messages.scrollHeight;
  }

  function hideTyping() {
    if (typing && typing.parentNode) typing.parentNode.removeChild(typing);
    typing = null;
  }

  function renderTopics(items) {
    topics.replaceChildren();
    (items || labels).forEach(function (label) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "nq-bot-chip";
      button.textContent = label;
      button.addEventListener("click", function () { ask(label); });
      topics.appendChild(button);
    });
  }

  async function ask(value) {
    var question = String(value || "").trim();
    if (!question || busy) return;
    addMessage(question, "user");
    input.value = "";
    busy = true;
    send.disabled = true;
    showTyping();

    try {
      var response = await fetch("/api/chat", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ message: question })
      });
      var data = await response.json();
      if (!response.ok) throw new Error(data.error || "Request failed");
      hideTyping();
      addMessage(data.text, "bot", data.links);
      renderTopics(data.menu);
    } catch (_) {
      hideTyping();
      addMessage("The guide is temporarily unavailable. Please try again or open the documentation links on the website.", "bot");
    } finally {
      hideTyping();
      busy = false;
      send.disabled = false;
      input.focus();
    }
  }

  launcher.addEventListener("click", function () {
    if (panel.getAttribute("aria-hidden") === "true") open();
    else close();
  });
  panel.querySelector("#nq-bot-close").addEventListener("click", close);
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    ask(input.value);
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && panel.getAttribute("aria-hidden") === "false") close();
  });

  renderTopics(labels);
  addMessage("Hi! I can guide you through NEXUS-Q, its PQC guides, SDKs, installation and documentation. Choose a topic or type a question.", "bot");
})();
