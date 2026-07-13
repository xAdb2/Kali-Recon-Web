// Task-create page: tool card toggling + expert command preview.
(function () {
  "use strict";
  var cfg = window.KRECON || {};

  function q(sel, root) { return (root || document).querySelector(sel); }
  function qa(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  // Show/hide expert block when a tool checkbox toggles.
  qa(".tool-check").forEach(function (chk) {
    chk.addEventListener("change", function () {
      var block = q('.expert[data-tool="' + chk.dataset.tool + '"]');
      if (block) block.hidden = !chk.checked;
    });
  });

  if (!cfg.expertEnabled) return;

  qa(".expert-toggle").forEach(function (toggle) {
    toggle.addEventListener("change", function () {
      var tool = toggle.dataset.tool;
      var mode = q('.mode-input[data-tool="' + tool + '"]');
      var cmd = q('.expert-cmd[data-tool="' + tool + '"]');
      if (toggle.checked) {
        mode.value = "EXPERT";
        cmd.disabled = false;
        if (!cmd.value.trim()) requestPreview(tool); // fetch default to prefill
      } else {
        mode.value = "DEFAULT";
        cmd.disabled = true;
      }
    });
  });

  qa(".expert-cmd").forEach(function (cmd) {
    var t;
    cmd.addEventListener("input", function () {
      clearTimeout(t);
      t = setTimeout(function () { requestPreview(cmd.dataset.tool); }, 400);
    });
  });

  function requestPreview(tool) {
    var cmd = q('.expert-cmd[data-tool="' + tool + '"]');
    var preview = q('.expert-preview[data-tool="' + tool + '"]');
    var msg = q('.preview-msg[data-tool="' + tool + '"]');
    var payload = {
      tool: tool,
      command: cmd ? cmd.value.trim() : "",
      target_ip: (q('[name=target_ip]') || {}).value || "",
      target_url: (q('[name=target_url]') || {}).value || "",
      profile: (q('[name=profile]') || {}).value || "SAFE",
      rate_limit: (q('[name=rate_limit]') || {}).value || 50
    };
    fetch(cfg.previewUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": cfg.csrf },
      body: JSON.stringify(payload)
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data.ok) {
        if (data.default && cmd && !cmd.value.trim()) cmd.value = data.default;
        preview.value = data.normalized || "";
        msg.textContent = data.normalized ? "✔ 已驗證，實際執行命令如上（輸出路徑由後端注入）。" : "";
        msg.className = "preview-msg small ok";
      } else {
        preview.value = "";
        msg.textContent = "✘ " + (data.error || "驗證失敗");
        msg.className = "preview-msg small error";
      }
    }).catch(function () {
      msg.textContent = "預覽請求失敗。";
    });
  }
})();
