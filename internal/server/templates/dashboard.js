// Dashboard behaviors shared by the initial page and tunnel refreshes.
(function () {
  "use strict";

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy]");
    if (!button || !navigator.clipboard) {
      return;
    }
    navigator.clipboard.writeText(button.getAttribute("data-copy")).then(function () {
      button.classList.add("copied");
      setTimeout(function () { button.classList.remove("copied"); }, 1200);
    });
  });

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-confirm")) {
      return;
    }
    event.preventDefault();
    if (form.querySelector(".confirm")) {
      return;
    }
    var trigger = form.querySelector("button[type=submit]");
    trigger.hidden = true;
    var confirmation = document.createElement("span");
    confirmation.className = "confirm";
    confirmation.append(document.createTextNode(form.getAttribute("data-confirm") + " "));

    var yes = document.createElement("button");
    yes.type = "button";
    yes.textContent = "yes";
    yes.addEventListener("click", function () { form.submit(); });

    var no = document.createElement("button");
    no.type = "button";
    no.textContent = "cancel";
    no.addEventListener("click", function () {
      confirmation.remove();
      trigger.hidden = false;
    });

    confirmation.append(yes, no);
    form.appendChild(confirmation);
  });

  var refreshingTunnels = false;

  function refreshTunnels() {
    var list = document.getElementById("tunnel-list");
    if (!list || list.querySelector(".confirm") || refreshingTunnels) {
      return;
    }
    refreshingTunnels = true;
    fetch("/dashboard/tunnels", { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("tunnel refresh failed");
        }
        return response.text();
      })
      .then(function (html) {
        var template = document.createElement("template");
        template.innerHTML = html;
        template.content.querySelectorAll("[data-dashboard-count]").forEach(function (count) {
          var current = document.getElementById(count.id);
          if (current) {
            current.textContent = count.textContent;
          }
          count.remove();
        });
        list.replaceChildren(template.content);
        tick();
      })
      .catch(function () {})
      .finally(function () {
        refreshingTunnels = false;
      });
  }

  function tick() {
    var now = Math.floor(Date.now() / 1000);
    document.querySelectorAll("[data-connected]").forEach(function (element) {
      var seconds = now - parseInt(element.getAttribute("data-connected"), 10);
      if (!isFinite(seconds) || seconds < 0) {
        return;
      }
      var hours = Math.floor(seconds / 3600);
      var minutes = Math.floor((seconds % 3600) / 60);
      if (hours >= 24) {
        element.textContent = Math.floor(hours / 24) + "d " + (hours % 24) + "h";
        return;
      }
      element.textContent = hours + ":" + String(minutes).padStart(2, "0") + ":" + String(seconds % 60).padStart(2, "0");
    });
  }

  tick();
  setInterval(tick, 1000);
  setInterval(refreshTunnels, 5000);
})();
