/* CVE-2026-109618 console front-end (recon / oneclick dual mode, no generic web scanning) */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var state = { job: null, snap: null, timer: null, sel: null };

  var VERDICT_BADGE = {
    RCE_CONFIRMED: "b-found", RCE_LIKELY: "b-likely", AFFECTED: "b-likely",
    NEEDS_PRECOND_PROBE: "b-unknown",
    DOS_ONLY: "b-dos", UNKNOWN_VERSION: "b-unknown",
    NOT_AFFECTED: "b-clean", NO_SINK: "b-clean",
    UNREACHABLE: "b-error", DENIED: "b-error", UNKNOWN: "b-unknown",
    TIMEOUT: "b-error"
  };
  var STATUS_BADGE = {
    found: "b-found", likely: "b-likely", dos: "b-dos", clean: "b-clean",
    unknown: "b-unknown", denied: "b-error", error: "b-error",
    no_sink: "b-nosink",
    running: "b-running", queued: "b-queued", stopped: "b-unknown"
  };

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function mode() {
    var r = document.querySelector('input[name="mode"]:checked');
    return r ? r.value : "recon";
  }

  function num(id, dflt) {
    var v = $(id).value.trim();
    var n = parseFloat(v);
    return isNaN(n) ? dflt : n;
  }

  function api(path, opts) {
    return fetch(path, opts).then(function (r) {
      return r.text().then(function (t) {
        var data = null;
        try { data = t ? JSON.parse(t) : null; } catch (e) { data = { raw: t }; }
        if (!r.ok) {
          var msg = (data && (data.error || data.msg)) || ("HTTP " + r.status);
          throw new Error(msg);
        }
        return data;
      });
    });
  }

  function setHealth(ok, text) {
    var el = $("health");
    el.textContent = text;
    el.className = "badge " + (ok ? "b-clean" : "b-error");
  }

  function refreshFast() {
    var fast = $("fast").checked;
    var deep = $("deep").checked && !fast;
    $("deep").disabled = fast;
    ["budget", "delay", "probe_sizes"].forEach(function (id) {
      $(id).disabled = fast || !deep;
    });
  }

  function refreshMode() {
    var m = mode();
    $("recon-opts").classList.toggle("dim", m !== "recon");
    $("attack-opts").classList.toggle("dim", m !== "oneclick");
    $("attack_ack").disabled = (m !== "oneclick");
    refreshFast();
  }

  function payload() {
    var targets = $("targets").value.split(/[\r\n]+/).map(function (s) { return s.trim(); })
      .filter(function (s) { return s && s[0] !== "#"; });
    if (!targets.length) { throw new Error("Please enter target URLs first (one per line)"); }
    var body = {
      targets: targets,
      mode: mode(),
      concurrency: num("concurrency", 16),
      timeout: num("timeout", 20),
      per_target_timeout: num("per_target_timeout", 900),
      insecure: $("insecure").checked
    };
    if (body.mode === "recon") {
      body.fast = $("fast").checked;
      body.deep = $("fast").checked ? false : $("deep").checked;
      body.budget = num("budget", 6);
      body.delay = num("delay", 0.3);
      body.probe_sizes = $("probe_sizes").value.trim() || "0.5,1,2,4,8,16";
    } else {
      body.attack_ack = $("attack_ack").checked;
      body.rounds = num("rounds", 6);
      body.tries = num("tries", 2);
      body.only = ($("only").value.trim() || "id").slice(0, 12);
    }
    return body;
  }

  function start() {
    var body;
    try { body = payload(); } catch (e) { alert(e.message); return; }
    $("start").disabled = true;
    api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) {
      state.job = r.job_id;
      state.sel = null;
      $("stop").disabled = false;
      poll(true);
    }).catch(function (e) {
      $("start").disabled = false;
      alert("Failed to start: " + e.message);
    });
  }

  function stop() {
    if (!state.job) { return; }
    api("/api/job/" + state.job + "/stop", { method: "POST" })
      .catch(function () {});
  }

  function poll(immediate) {
    if (state.timer) { clearTimeout(state.timer); state.timer = null; }
    if (!state.job) { return; }
    api("/api/job/" + state.job).then(function (snap) {
      state.snap = snap;
      render(snap);
      var done = snap.status === "done" || snap.status === "stopped" || snap.status === "error";
      if (done) {
        $("start").disabled = false;
        $("stop").disabled = true;
      } else {
        state.timer = setTimeout(function () { poll(false); }, immediate ? 200 : 1200);
      }
    }).catch(function (e) {
      setHealth(false, "Failed to read job: " + e.message);
      state.timer = setTimeout(function () { poll(false); }, 3000);
    });
  }

  function evidenceLine(t) {
    var ev = t.evidence || {};
    var bits = [];
    if (ev.verdict) { bits.push(ev.verdict); }
    if (ev.version) { bits.push("PHP " + ev.version); }
    if (ev.oom_at_mb != null) { bits.push("OOM@" + ev.oom_at_mb + "MB"); }
    if (ev.post_max_gt_memory) { bits.push("post_max&gt;memory_limit"); }
    if (ev.sink) { bits.push("sink " + ev.sink); }
    if (ev.proof_body) { bits.push("proof " + String(ev.proof_body).replace(/\s+/g, " ").slice(0, 60)); }
    if (ev.report_error) { bits.push("report: " + String(ev.report_error).slice(0, 60)); }
    return bits.join(" · ") || (t.summary || "-");
  }

  function match(t) {
    var q = $("q").value.trim().toLowerCase();
    var fv = $("f-verdict").value;
    var fs = $("f-status").value;
    if (fv && (t.verdict || "") !== fv) { return false; }
    if (fs && (t.status || "") !== fs) { return false; }
    if (!q) { return true; }
    var hay = [t.url, t.verdict, t.status, t.summary, evidenceLine(t)].join(" ").toLowerCase();
    return hay.indexOf(q) >= 0;
  }

  function render(snap) {
    var tgl = snap.targets || [];
    var done = 0, rce = 0, likely = 0, clean = 0;
    tgl.forEach(function (t) {
      if (t.status && ["found", "likely", "dos", "clean", "unknown", "denied", "error"].indexOf(t.status) >= 0) { done++; }
      if (t.verdict === "RCE_CONFIRMED") { rce++; }
      else if (t.verdict === "RCE_LIKELY" || t.verdict === "AFFECTED" || t.verdict === "DOS_ONLY") { likely++; }
      else if (t.status === "clean" || t.status === "unknown") { clean++; }
    });
    $("s-job").textContent = snap.job_id || "-";
    if (snap.job_id) {
      $("exp-json").href = "/api/job/" + snap.job_id + "/export.json";
      $("exp-csv").href = "/api/job/" + snap.job_id + "/export.csv";
    }
    $("s-total").textContent = snap.total || tgl.length;
    $("s-done").textContent = done;
    $("s-rce").textContent = rce;
    $("s-likely").textContent = likely;
    $("s-clean").textContent = clean;
    $("progress-text").textContent = (snap.status || "-") + " · " + done + "/" + (snap.total || tgl.length) +
      (snap.elapsed != null ? " · " + Math.round(snap.elapsed) + "s" : "");

    var rows = tgl.filter(match);

    var RENDER_CAP = 300;

    var shown = rows.length > RENDER_CAP ? rows.slice(0, RENDER_CAP) : rows;
    var tb = $("rows");
    if (!rows.length) {
      tb.innerHTML = '<tr class="empty"><td colspan="8">No matching targets</td></tr>';
    } else {
      tb.innerHTML = shown.map(function (t) {
        var vb = VERDICT_BADGE[t.verdict] || "b-unknown";
        var sb = STATUS_BADGE[t.status] || "b-queued";
        var ev = t.evidence || {};
        return '<tr data-idx="' + t.idx + '">' +
          '<td class="c">' + t.idx + '</td>' +
          '<td class="url">' + esc(t.url) + '</td>' +
          '<td class="mono">' + esc((ev.mode || (snap.opts && snap.opts.mode) || "recon")) + '</td>' +
          '<td><span class="badge ' + vb + '">' + esc(t.verdict || "-") + '</span></td>' +
          '<td class="c mono">' + esc(t.rc == null ? "-" : t.rc) + '</td>' +
          '<td class="mono">' + esc(ev.version || "-") + '</td>' +
          '<td class="ev">' + evidenceLine(t) + '</td>' +
          '<td><span class="badge ' + sb + '">' + esc(t.status || "-") + '</span></td>' +
          '</tr>';
      }).join("") + (rows.length > RENDER_CAP
        ? '<tr class="empty"><td colspan="8">Only the first ' + RENDER_CAP + ' rows are rendered (matched ' + rows.length +
          ' of ' + tgl.length + ') — use "Export JSON/CSV" to view the rest, so large lists do not slow the browser</td></tr>'
        : "");
    }
    Array.prototype.forEach.call(tb.querySelectorAll("tr[data-idx]"), function (tr) {
      tr.addEventListener("click", function () {
        state.sel = parseInt(tr.getAttribute("data-idx"), 10);
        showDetail();
      });
    });
    if (state.sel != null) { showDetail(); }
  }

  function findTarget() {
    var tgl = (state.snap && state.snap.targets) || [];
    for (var i = 0; i < tgl.length; i++) { if (tgl[i].idx === state.sel) { return tgl[i]; } }
    return null;
  }

  function showDetail() {
    var t = findTarget();
    var box = $("detail");
    if (!t) { box.classList.add("hidden"); return; }
    box.classList.remove("hidden");
    $("d-url").textContent = t.url;
    var ev = t.evidence || {};
    var meta = [
      ["Verdict", t.verdict || "-"], ["Status", t.status || "-"], ["rc", t.rc == null ? "-" : t.rc],
      ["Mode", ev.mode || "-"], ["PHP", ev.version || "-"], ["sink", ev.sink || "-"],
      ["profile", ev.profile || "-"], ["RCE", ev.rce ? "yes" : "no"],
      ["post_max>memory_limit", ev.post_max_gt_memory == null ? "-" : (ev.post_max_gt_memory ? "true" : "false")],
      ["OOM@MB", ev.oom_at_mb == null ? "-" : ev.oom_at_mb],
      ["proof_url", ev.proof_url || "-"], ["postex_rc", ev.postex_rc == null ? "-" : ev.postex_rc]
    ];
    $("d-meta").innerHTML = meta.map(function (kv) {
      return '<span class="kv"><i>' + esc(kv[0]) + '</i><b class="mono">' + esc(kv[1]) + '</b></span>';
    }).join("");
    var fs = t.findings || [];
    $("d-findings").innerHTML = fs.length ? fs.map(function (f) {
      return '<div class="finding sev-critical"><b>' + esc(f.title || f.type) +
        '</b><div class="mono small">' + esc(f.detail || "") + '</div></div>';
    }).join("") : "";
    $("d-evidence").textContent = JSON.stringify(ev, null, 2);
    $("d-log").textContent = t.log || "-";
  }

  function boot() {
    $("start").addEventListener("click", start);
    $("stop").addEventListener("click", stop);
    $("d-close").addEventListener("click", function () { $("detail").classList.add("hidden"); state.sel = null; });
    Array.prototype.forEach.call(document.querySelectorAll('input[name="mode"]'), function (r) {
      r.addEventListener("change", refreshMode);
    });
    $("q").addEventListener("input", function () { if (state.snap) { render(state.snap); } });
    $("fast").addEventListener("change", refreshFast);
    $("deep").addEventListener("change", refreshFast);
    $("f-verdict").addEventListener("change", function () { if (state.snap) { render(state.snap); } });
    $("f-status").addEventListener("change", function () { if (state.snap) { render(state.snap); } });
    $("recent").addEventListener("click", function () {
      api("/api/jobs").then(function (r) {
        var jobs = (r && r.jobs) || [];
        if (!jobs.length) { alert("No recent jobs"); return; }
        state.job = jobs[0].job_id;
        state.sel = null;
        poll(true);
      }).catch(function (e) { alert("Failed to read job list: " + e.message); });
    });
    refreshMode();
    api("/api/health").then(function (h) {
      setHealth(true, "Service OK" + (h && h.version ? " " + h.version : ""));
    }).catch(function (e) { setHealth(false, "Service error: " + e.message); });
    api("/api/jobs").then(function (r) {
      var jobs = (r && r.jobs) || [];
      if (jobs.length && jobs[0].status === "running") {
        state.job = jobs[0].job_id;
        $("stop").disabled = false;
        poll(false);
      }
    }).catch(function () {});
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
