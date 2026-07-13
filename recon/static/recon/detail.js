// Task-detail page: tab switching + status polling (no full page refresh).
(function () {
  "use strict";
  var cfg = window.KRECON_TASK || {};

  function qa(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }
  function q(sel) { return document.querySelector(sel); }

  qa(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () {
      qa(".tab").forEach(function (t) { t.classList.remove("active"); });
      qa(".tabpane").forEach(function (p) { p.classList.remove("active"); });
      tab.classList.add("active");
      var pane = q("#tab-" + tab.dataset.tab);
      if (pane) pane.classList.add("active");
    });
  });

  var logSeen = {};

  function badge(status, display) {
    return '<span class="badge s-' + status + '">' + display + "</span>";
  }

  function poll() {
    fetch(cfg.statusUrl, { headers: { "X-Requested-With": "fetch" } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var st = q("#task-status");
        if (st) st.outerHTML = '<span class="badge s-' + data.status + '" id="task-status">' + data.status_display + "</span>";
        var pg = q("#task-progress"); if (pg) pg.textContent = data.progress;
        var fill = q("#progressfill"); if (fill) fill.style.width = data.progress + "%";

        data.steps.forEach(function (s) {
          var row = q('#steps-table tr[data-order="' + s.order + '"]');
          if (!row) return;
          row.querySelector(".col-status").innerHTML = badge(s.status, s.status_display);
          row.querySelector(".col-exit").textContent = (s.exit_code === null ? "—" : s.exit_code);
          row.querySelector(".col-dur").textContent = (s.duration === null ? "—" : s.duration);
          var key = s.order + ":" + s.status;
          if (!logSeen[key]) {
            logSeen[key] = true;
            addLog("[" + s.order + "] " + s.title + " → " + s.status_display +
                   (s.error_summary ? " (" + s.error_summary + ")" : ""));
          }
        });

        if (data.is_terminal) {
          addLog("任務已結束：" + data.status_display);
          setTimeout(function () { window.location.reload(); }, 1500);
        } else {
          setTimeout(poll, 3000);
        }
      })
      .catch(function () { setTimeout(poll, 5000); });
  }

  function addLog(text) {
    var list = q("#log-list");
    if (!list) return;
    var li = document.createElement("li");
    li.textContent = new Date().toLocaleTimeString() + "  " + text;
    list.insertBefore(li, list.firstChild);
  }

  if (!cfg.isTerminal) poll(); else addLog("任務已結束。");
})();
