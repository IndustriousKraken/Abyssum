// Live scan progress. The scan-detail page carries a #live element with a
// data-session attribute; this opens the per-session WebSocket and swaps in the
// server-rendered progress fragments as they arrive. Plain vanilla JS so it
// works without vendoring an HTMX WebSocket extension; HTMX still drives the
// rest of the page (fragment swaps) via its hx-* attributes.
(function () {
  var el = document.getElementById("live");
  if (!el) return;
  var id = el.getAttribute("data-session");
  if (!id) return;
  var proto = location.protocol === "https:" ? "wss:" : "ws:";
  var ws = new WebSocket(proto + "//" + location.host + "/ws/" + id);
  ws.onmessage = function (ev) {
    el.innerHTML = ev.data;
    // When the scan reaches a terminal state the server marks the fragment;
    // refresh the persisted results below it via HTMX if present.
    if (ev.data.indexOf('data-terminal="true"') !== -1) {
      var results = document.getElementById("results");
      if (results && window.htmx) window.htmx.trigger(results, "refresh");
    }
  };
  ws.onclose = function () {
    var results = document.getElementById("results");
    if (results && window.htmx) window.htmx.trigger(results, "refresh");
  };
})();
