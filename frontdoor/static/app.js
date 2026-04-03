const PRESETS = {
  support: { temperature: 0.0, max_tokens: 2048, summary: "Grounded help lane" },
  operations: { temperature: 0.1, max_tokens: 1200, summary: "Live organism inspection lane" },
  build: { temperature: 0.2, max_tokens: 1600, summary: "System build lane" },
};

const state = {
  token: sessionStorage.getItem("securecore_token") || "",
  conversationId: "",
  branchId: "main",
  mode: "support",
  selectedBlock: null,
};

const elements = {
  loginPanel: document.getElementById("login-panel"),
  loginForm: document.getElementById("login-form"),
  loginButton: document.getElementById("login-button"),
  loginError: document.getElementById("login-error"),
  chatShell: document.getElementById("chat-shell"),
  logoutButton: document.getElementById("logout-button"),
  trustState: document.getElementById("trust-state"),
  inferenceName: document.getElementById("inference-name"),
  branchName: document.getElementById("branch-name"),
  modeSummary: document.getElementById("mode-summary"),
  inferenceSummary: document.getElementById("inference-summary"),
  messageStream: document.getElementById("message-stream"),
  emptyState: document.getElementById("empty-state"),
  messageInput: document.getElementById("message-input"),
  sendButton: document.getElementById("send-button"),
  conversationLabel: document.getElementById("conversation-label"),
  identityLabel: document.getElementById("identity-label"),
  blockMenu: document.getElementById("block-menu"),
  blockMenuLabel: document.getElementById("block-menu-label"),
  noteButton: document.getElementById("block-note-button"),
  citeButton: document.getElementById("block-cite-button"),
  continueButton: document.getElementById("block-continue-button"),
};

function setMode(mode) {
  state.mode = mode in PRESETS ? mode : "support";
  const preset = PRESETS[state.mode];
  elements.modeSummary.textContent = preset.summary;
  elements.inferenceSummary.textContent = `temp ${preset.temperature.toFixed(1)} • max ${preset.max_tokens}`;
}

function setTrust(trust) {
  const trustState = trust?.state || "UNKNOWN";
  elements.trustState.textContent = trustState;
  elements.trustState.className = `trust ${trustState === "FULL" ? "trust-full" : "trust-reduced"}`;
}

function setInference(inference) {
  elements.inferenceName.textContent = "Local Ollama API";
}

function setConversationLabels() {
  elements.branchName.textContent = state.branchId || "main";
  elements.conversationLabel.textContent = state.conversationId
    ? `Conversation ${state.conversationId}`
    : "No conversation yet";
  elements.identityLabel.textContent = state.token ? "JWT identity active" : "JWT identity required";
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (state.token) {
    headers.set("Authorization", `Bearer ${state.token}`);
  }

  const response = await fetch(path, { ...options, headers });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : { ok: response.ok, error: await response.text() };

  if (!response.ok || payload.ok === false) {
    const message = payload?.error || `Request failed: ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;");
}

function blockActions(block) {
  const noteBadge = `<span class="badge">notes ${block.note_count || 0}</span>`;
  const citeBadge = `<span class="badge">cites ${block.citation_count || 0}</span>`;
  return `${noteBadge}${citeBadge}`;
}

function renderMessages(messages) {
  elements.messageStream.innerHTML = "";
  if (!messages.length) {
    elements.messageStream.appendChild(elements.emptyState);
    return;
  }

  for (const message of messages) {
    const article = document.createElement("article");
    article.className = `message message-${message.role}`;

    const header = document.createElement("header");
    header.className = "message-header";
    header.innerHTML = `
      <span class="message-role">${escapeHtml(message.role)}</span>
      <span class="message-meta">${escapeHtml(message.mode)} • ${escapeHtml(message.branch_id)}</span>
    `;
    article.appendChild(header);

    const blocksWrap = document.createElement("div");
    blocksWrap.className = "message-blocks";

    for (const block of message.blocks) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "block";
      button.dataset.messageId = message.message_id;
      button.dataset.blockId = block.block_id;
      button.innerHTML = `
        <span class="block-content">${escapeHtml(block.content)}</span>
        <span class="block-badges">${blockActions(block)}</span>
      `;
      blocksWrap.appendChild(button);
    }

    article.appendChild(blocksWrap);
    elements.messageStream.appendChild(article);
  }

  elements.messageStream.scrollTop = elements.messageStream.scrollHeight;
}

async function loadHistory() {
  if (!state.conversationId) {
    renderMessages([]);
    return;
  }

  const payload = await api(`/api/chat/history?conversation_id=${encodeURIComponent(state.conversationId)}&branch_id=${encodeURIComponent(state.branchId)}`);
  setTrust(payload.trust);
  renderMessages(payload.messages || []);
  setConversationLabels();
}

async function login(event) {
  event.preventDefault();
  elements.loginError.textContent = "";
  elements.loginButton.disabled = true;

  try {
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    const payload = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
      headers: {},
    });

    state.token = payload.access_token || "";
    sessionStorage.setItem("securecore_token", state.token);
    elements.loginPanel.classList.add("hidden");
    elements.chatShell.classList.remove("hidden");
    setMode(state.mode);
    setConversationLabels();
  } catch (error) {
    elements.loginError.textContent = error.message;
  } finally {
    elements.loginButton.disabled = false;
  }
}

async function sendMessage() {
  const message = elements.messageInput.value.trim();
  if (!message) {
    return;
  }

  elements.sendButton.disabled = true;
  try {
    const payload = await api("/api/chat/send", {
      method: "POST",
      body: JSON.stringify({
        message,
        mode: state.mode,
        conversation_id: state.conversationId || undefined,
        branch_id: state.branchId || undefined,
      }),
    });

    state.conversationId = payload.conversation_id;
    state.branchId = payload.branch_id || "main";
    setTrust(payload.trust);
    setInference(payload.inference);
    setConversationLabels();
    elements.messageInput.value = "";
    await loadHistory();
  } catch (error) {
    window.alert(error.message);
  } finally {
    elements.sendButton.disabled = false;
  }
}

function openBlockMenu(target, event) {
  const rect = target.getBoundingClientRect();
  state.selectedBlock = {
    messageId: target.dataset.messageId,
    blockId: target.dataset.blockId,
  };
  elements.blockMenuLabel.textContent = `Block ${state.selectedBlock.blockId}`;
  elements.blockMenu.style.top = `${window.scrollY + rect.bottom + 6}px`;
  elements.blockMenu.style.left = `${window.scrollX + rect.left}px`;
  elements.blockMenu.classList.remove("hidden");
  event.stopPropagation();
}

function closeBlockMenu() {
  state.selectedBlock = null;
  elements.blockMenu.classList.add("hidden");
}

async function addNote() {
  const selected = state.selectedBlock;
  if (!selected) {
    return;
  }
  const content = window.prompt("Note for this block:");
  if (!content) {
    return;
  }
  await api("/api/chat/note", {
    method: "POST",
    body: JSON.stringify({
      conversation_id: state.conversationId,
      branch_id: state.branchId,
      message_id: selected.messageId,
      block_id: selected.blockId,
      content,
    }),
  });
  closeBlockMenu();
  await loadHistory();
}

async function addCitation() {
  const selected = state.selectedBlock;
  if (!selected) {
    return;
  }
  const sourceRef = window.prompt("Citation source reference:");
  if (!sourceRef) {
    return;
  }
  const excerpt = window.prompt("Optional excerpt:") || "";
  await api("/api/chat/cite", {
    method: "POST",
    body: JSON.stringify({
      conversation_id: state.conversationId,
      branch_id: state.branchId,
      message_id: selected.messageId,
      block_id: selected.blockId,
      source_type: "operator_ref",
      source_ref: sourceRef,
      excerpt,
    }),
  });
  closeBlockMenu();
  await loadHistory();
}

async function continueChat() {
  const selected = state.selectedBlock;
  if (!selected) {
    return;
  }
  const payload = await api("/api/chat/branch", {
    method: "POST",
    body: JSON.stringify({
      conversation_id: state.conversationId,
      parent_message_id: selected.messageId,
      parent_block_id: selected.blockId,
      mode: state.mode,
      reason: "continue_chat",
    }),
  });
  state.branchId = payload.branch_id;
  setTrust(payload.trust);
  setConversationLabels();
  closeBlockMenu();
  await loadHistory();
}

function logout() {
  state.token = "";
  state.conversationId = "";
  state.branchId = "main";
  sessionStorage.removeItem("securecore_token");
  renderMessages([]);
  setConversationLabels();
  elements.chatShell.classList.add("hidden");
  elements.loginPanel.classList.remove("hidden");
}

document.addEventListener("click", (event) => {
  const block = event.target.closest(".block");
  if (block) {
    openBlockMenu(block, event);
    return;
  }
  if (!event.target.closest("#block-menu")) {
    closeBlockMenu();
  }
});

elements.loginForm.addEventListener("submit", login);
elements.sendButton.addEventListener("click", sendMessage);
elements.logoutButton.addEventListener("click", logout);
elements.noteButton.addEventListener("click", () => addNote().catch((error) => window.alert(error.message)));
elements.citeButton.addEventListener("click", () => addCitation().catch((error) => window.alert(error.message)));
elements.continueButton.addEventListener("click", () => continueChat().catch((error) => window.alert(error.message)));
elements.messageInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    sendMessage().catch((error) => window.alert(error.message));
  }
});

for (const radio of document.querySelectorAll('input[name="mode"]')) {
  radio.addEventListener("change", () => setMode(radio.value));
}

setMode(state.mode);
setConversationLabels();
setTrust({ state: "FULL" });
if (state.token) {
  elements.loginPanel.classList.add("hidden");
  elements.chatShell.classList.remove("hidden");
}
