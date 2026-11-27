"use strict";

// the desktop updater's signed feed lists the current release's packages
const FEED_URL = "https://rselbach.github.io/scimtest/update.json";
const SIGNING_CONTEXT = "scimtest-update-feed-v1\n";
const FEED_PUBLIC_KEY_B64 = "2obyIySbPw8xSuXQwzSw2sCbOixUww08jk95se82unc=";
const ARTIFACT_PREFIX = "https://github.com/rselbach/scimtest/releases/download/";
const NOTES_PREFIX = "https://github.com/rselbach/scimtest/";

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

function decodeBase64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function isAllowedURL(raw, prefix) {
  if (typeof raw !== "string" || !raw.startsWith(prefix)) {
    return false;
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return false;
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    raw.includes("?") ||
    raw.includes("#")
  ) {
    return false;
  }
  const rest = raw.slice(prefix.length);
  if (!rest) {
    return false;
  }
  for (const segment of rest.split("/")) {
    let decoded;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      return false;
    }
    if (
      segment === "." ||
      segment === ".." ||
      decoded === "." ||
      decoded === ".." ||
      decoded.includes("/") ||
      decoded.includes("\\")
    ) {
      return false;
    }
  }
  return true;
}

async function verifyAndDecodeFeed(feed) {
  if (!feed || typeof feed.payload !== "string" || typeof feed.signature !== "string") {
    throw new Error("update feed envelope is malformed");
  }
  const payloadBytes = decodeBase64(feed.payload);
  const signatureBytes = decodeBase64(feed.signature);
  const publicKeyBytes = decodeBase64(FEED_PUBLIC_KEY_B64);

  const contextBytes = new TextEncoder().encode(SIGNING_CONTEXT);
  const signedMessage = new Uint8Array(contextBytes.length + payloadBytes.length);
  signedMessage.set(contextBytes, 0);
  signedMessage.set(payloadBytes, contextBytes.length);

  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is unavailable for feed signature verification");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    publicKeyBytes,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify("Ed25519", key, signatureBytes, signedMessage);
  if (!valid) {
    throw new Error("update feed signature verification failed");
  }

  const release = JSON.parse(new TextDecoder().decode(payloadBytes));
  if (
    !release ||
    release.schema !== 1 ||
    release.app !== "com.rselbach.scimtest" ||
    release.channel !== "stable" ||
    typeof release.version !== "string" ||
    !release.version ||
    !Array.isArray(release.artifacts)
  ) {
    throw new Error("update feed payload is malformed");
  }
  if (!isAllowedURL(release.notes_url, NOTES_PREFIX)) {
    throw new Error("update feed notes URL is not allowed");
  }
  for (const artifact of release.artifacts) {
    if (!artifact || !isAllowedURL(artifact.url, ARTIFACT_PREFIX)) {
      throw new Error("update feed artifact URL is not allowed");
    }
  }
  return release;
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
  .then((feed) => verifyAndDecodeFeed(feed))
  .then((release) => render(release))
  .catch((err) => console.error("scimtest: could not load the latest release", err));
