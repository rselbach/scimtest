"use strict";

// the desktop updater's signed feed lists the current release's packages
const FEED_URL = "https://rselbach.github.io/scimtest/update.json";

const LABELS = {
  dmg: "macOS DMG",
  "app-zip": "macOS ZIP",
  deb: ".deb",
  rpm: ".rpm",
  "pkg.tar.zst": ".pkg.tar.zst",
};

function detectPlatform() {
  const ua = navigator.userAgent;
  const platform = navigator.userAgentData?.platform ?? "";
  if (/Android|iPhone|iPad/.test(ua) || navigator.userAgentData?.mobile) {
    return null;
  }
  if (platform === "macOS" || /Macintosh/.test(ua)) {
    // iPadOS reports a desktop Mac user agent
    return navigator.maxTouchPoints > 1 ? null : "macos";
  }
  if ((platform === "Linux" || /Linux/.test(ua)) && !/aarch64|arm/i.test(ua)) {
    return "linux";
  }
  return null;
}

function primaryKind(os) {
  if (os === "macos") {
    return "dmg";
  }
  if (os === "linux") {
    return /Fedora|Red Hat/.test(navigator.userAgent) ? "rpm" : "deb";
  }
  return null;
}

function decodeFeed(feed) {
  const bytes = Uint8Array.from(atob(feed.payload), (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

function link(text, href) {
  const a = document.createElement("a");
  a.textContent = text;
  a.href = href;
  return a;
}

function render(release) {
  const os = detectPlatform();
  const kind = primaryKind(os);
  const primary = release.artifacts.find((a) => a.os === os && a.kind === kind);
  const button = document.getElementById("download");
  const label = document.getElementById("download-label");
  const meta = document.getElementById("download-meta");
  const version = link(`v${release.version}`, release.notes_url);

  meta.replaceChildren(version);
  if (primary) {
    button.href = primary.url;
    label.textContent = os === "macos" ? "Download for macOS" : "Download for Linux";
    const detail = os === "macos" ? "Apple silicon, macOS 26 or later" : `x86_64 ${LABELS[kind]}`;
    meta.append(` · ${detail}`);
  } else {
    label.textContent = "View releases";
    meta.append(" · macOS (Apple silicon) and Linux x86_64");
  }
  document.getElementById("brew").hidden = os !== "macos";

  const others = document.getElementById("others");
  const rest = release.artifacts.filter((a) => a !== primary);
  others.replaceChildren(primary ? "Other downloads: " : "Downloads: ");
  rest.forEach((a, i) => {
    if (i > 0) {
      others.append(" · ");
    }
    others.append(link(LABELS[a.kind] ?? a.kind, a.url));
  });
  others.hidden = rest.length === 0;
}

fetch(FEED_URL)
  .then((response) => {
    if (!response.ok) {
      throw new Error(`update feed returned ${response.status}`);
    }
    return response.json();
  })
  .then((feed) => render(decodeFeed(feed)))
  .catch((err) => console.error("scimtest: could not load the latest release", err));
