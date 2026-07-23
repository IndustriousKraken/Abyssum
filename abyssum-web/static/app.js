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

// Wordlist upload → textarea. A file input marked data-wordlist-file="<id>" reads
// the chosen .txt file client-side into the textarea with that id, so an upload
// becomes ordinary pasted text and the server never parses multipart form data.
(function () {
  var inputs = document.querySelectorAll("[data-wordlist-file]");
  Array.prototype.forEach.call(inputs, function (input) {
    input.addEventListener("change", function () {
      var file = input.files && input.files[0];
      if (!file) return;
      var target = document.getElementById(input.getAttribute("data-wordlist-file"));
      if (!target) return;
      var reader = new FileReader();
      reader.onload = function (e) {
        target.value = e.target.result;
      };
      reader.readAsText(file);
    });
  });
})();

// Engagement document upload → hidden fields. A file input marked data-doc-file
// reads the chosen file client-side into its form's hidden file_data (a base64
// data URL) and file_name inputs, so a binary upload (a PDF) travels as ordinary
// urlencoded form data and the server never parses multipart. The server decodes
// the bytes and detects the real type from them, ignoring the declared prefix.
(function () {
  var inputs = document.querySelectorAll("[data-doc-file]");
  Array.prototype.forEach.call(inputs, function (input) {
    input.addEventListener("change", function () {
      var form = input.form;
      var file = input.files && input.files[0];
      if (!form || !file) return;
      if (form.file_name) form.file_name.value = file.name;
      var reader = new FileReader();
      reader.onload = function (e) {
        if (form.file_data) form.file_data.value = e.target.result;
      };
      reader.readAsDataURL(file);
    });
  });
})();
