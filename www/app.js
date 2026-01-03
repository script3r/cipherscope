const numberFormatter = new Intl.NumberFormat("en-US");

const formatNumber = (value) => numberFormatter.format(value);

const escapeHtml = (value) =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");

const formatDate = (iso) => {
  const date = new Date(iso);
  return date.toUTCString().replace("GMT", "UTC");
};

const initCopyButtons = () => {
  document.querySelectorAll("[data-copy]").forEach((button) => {
    const target = document.querySelector(button.dataset.copy);
    if (!target) {
      return;
    }
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(target.textContent.trim());
        button.textContent = "Copied";
        setTimeout(() => {
          button.textContent = "Copy";
        }, 1600);
      } catch (error) {
        button.textContent = "Copy failed";
      }
    });
  });
};

const buildCard = (repo) => {
  const intensity = repo.filesScanned
    ? Math.min((repo.cryptoItems / repo.filesScanned) * 100, 100)
    : 0;
  const itemsPer1k = repo.filesScanned
    ? (repo.cryptoItems / repo.filesScanned) * 1000
    : 0;

  const card = document.createElement("article");
  card.className = "result-card";
  const evidenceHtml = repo.evidenceSamples && repo.evidenceSamples.length
    ? repo.evidenceSamples
        .map((sample) => {
          const contextLines = sample.context
            .map(
              (line) => `
                <div class="code-line ${line.highlight ? "highlight" : ""}">
                  <span class="line-no">${line.line}</span>
                  <span class="line-text">${escapeHtml(line.text || " ")}</span>
                </div>`
            )
            .join("");
          return `
            <div class="evidence-card">
              <div class="evidence-header">
                <span>${escapeHtml(sample.identifier)}</span>
                <span class="evidence-tag">${escapeHtml(sample.assetType)}</span>
              </div>
              <div class="evidence-path">${escapeHtml(sample.path)}:${sample.line}:${sample.column}</div>
              <div class="code-block">
                ${contextLines}
              </div>
            </div>
          `;
        })
        .join("")
    : `<div class="evidence-empty">No crypto matches detected in this repo.</div>`;
  card.innerHTML = `
    <div class="result-header">
      <div>
        <div class="result-title">${repo.name}</div>
        <div class="result-sub">${repo.languageFocus} focus</div>
      </div>
    </div>
    <div class="result-metrics">
      <div class="metric-card">
        <strong>${formatNumber(repo.cryptoItems)}</strong>
        crypto signals
      </div>
      <div class="metric-card">
        <strong>${formatNumber(repo.filesScanned)}</strong>
        files scanned
      </div>
      <div class="metric-card">
        <strong>${itemsPer1k.toFixed(1)}</strong>
        signals per 1k files
      </div>
      <div class="metric-card">
        <strong>${formatNumber(repo.uniqueFiles)}</strong>
        affected files
      </div>
    </div>
    <div>
      <div class="signal-bar"><span style="width: ${intensity}%"></span></div>
    </div>
    <div class="chip-row">
      ${
        repo.topIdentifiers.length
          ? repo.topIdentifiers
              .map(
                (item) =>
                  `<span class="chip">${item.label} - ${formatNumber(
                    item.count
                  )}</span>`
              )
              .join("")
          : `<span class="chip">No crypto matches detected</span>`
      }
    </div>
    <div class="evidence-section">
      <div class="evidence-title">Evidence trail</div>
      ${evidenceHtml}
    </div>
    <div class="result-sub">
      <a href="data/${repo.slug}.jsonl">Download JSONL evidence</a>
    </div>
  `;

  return card;
};

const loadResults = async () => {
  const response = await fetch("data/results.json");
  const data = await response.json();
  const grid = document.getElementById("results-grid");
  const generated = document.getElementById("results-generated");

  generated.textContent = formatDate(data.generatedAt);

  grid.innerHTML = "";
  data.repos.forEach((repo) => {
    grid.appendChild(buildCard(repo));
  });
};

const initLiveScan = () => {
  const form = document.getElementById("live-form");
  const codeInput = document.getElementById("live-code");
  const languageInput = document.getElementById("live-language");
  const results = document.getElementById("live-results");
  const counter = document.getElementById("live-counter");
  const sampleButton = document.getElementById("live-sample");
  if (!form || !codeInput || !languageInput || !results) {
    return;
  }

  const submitButton = form.querySelector("button[type=\"submit\"]");
  const MAX_CODE_BYTES = 64 * 1024;
  const sampleSnippets = {
    c: `#include <openssl/evp.h>

void demo() {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_sha256();
}`,
    cpp: `#include <openssl/evp.h>

int main() {
  auto *ctx = EVP_MD_CTX_new();
  EVP_sha256();
  return 0;
}`,
    java: `import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class Demo {
  void run(byte[] key, byte[] data) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    mac.doFinal(data);
  }
}`,
    python: `import hashlib

value = hashlib.sha256(b"hello").hexdigest()
`,
    go: `package main

import (
  "crypto/sha256"
  "fmt"
)

func main() {
  sum := sha256.Sum256([]byte("hello"))
  fmt.Println(sum)
}
`,
    swift: `import CryptoKit

let digest = SHA256.hash(data: Data("hello".utf8))
print(digest)
`,
    php: `<?php
$hash = hash('sha256', 'hello');
?>
`,
    objc: `#import <CommonCrypto/CommonCrypto.h>

void demo() {
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256("hello", 5, digest);
}
`,
    rust: `use sha2::{Digest, Sha256};

fn main() {
  let mut hasher = Sha256::new();
  hasher.update(b"hello");
  let _ = hasher.finalize();
}
`,
  };

  const getByteCount = (value) => new TextEncoder().encode(value).length;

  const modeForLanguage = (lang) => {
    switch (lang) {
      case "c":
        return "text/x-csrc";
      case "cpp":
        return "text/x-c++src";
      case "java":
        return "text/x-java";
      case "python":
        return "python";
      case "go":
        return "text/x-go";
      case "swift":
        return "swift";
      case "php":
        return "text/x-php";
      case "objc":
        return "text/x-objectivec";
      case "rust":
        return "rust";
      default:
        return "text/plain";
    }
  };

  const editor = window.CodeMirror
    ? window.CodeMirror.fromTextArea(codeInput, {
        lineNumbers: true,
        lineWrapping: true,
        mode: modeForLanguage(languageInput.value),
        viewportMargin: Infinity,
      })
    : null;

  let highlightedLineHandle = null;

  if (editor) {
    editor.setSize("100%", 260);
  }

  const getCodeValue = () => (editor ? editor.getValue() : codeInput.value || "");
  const setCodeValue = (value) => {
    if (editor) {
      editor.setValue(value);
      editor.focus();
      return;
    }
    codeInput.value = value;
  };

  const setStatus = (message) => {
    results.innerHTML = `<div class="live-status">${escapeHtml(message)}</div>`;
  };

  const updateCounter = (bytes) => {
    if (!counter) {
      return;
    }
    const kb = bytes / 1024;
    counter.textContent = `${kb.toFixed(1)} / 64 KB`;
  };

  const updateCounterFromInput = () => {
    updateCounter(getByteCount(getCodeValue()));
  };

  const renderItems = (items) => {
    if (!items.length) {
      results.innerHTML = `<div class="live-status">No crypto matches found.</div>`;
      return;
    }
    const list = items
      .map((item) => {
        const metadata = item.metadata && Object.keys(item.metadata).length
          ? Object.entries(item.metadata)
              .map(([key, value]) => {
                const display = typeof value === "object"
                  ? JSON.stringify(value)
                  : value;
                return `${key}: ${display}`;
              })
              .join(", ")
          : "";
        return `
          <div class="live-item" data-line="${item.evidence.line}" data-column="${item.evidence.column}">
            <div class="live-item-header">
              <span>${escapeHtml(item.identifier)}</span>
              <span class="live-pill">${escapeHtml(item.assetType)}</span>
            </div>
            <div class="live-item-meta">${escapeHtml(item.path)}:${item.evidence.line}:${item.evidence.column}</div>
            ${
              metadata
                ? `<div class="live-item-meta">${escapeHtml(metadata)}</div>`
                : ""
            }
          </div>
        `;
      })
      .join("");
    results.innerHTML = `
      <div class="live-status">Found ${items.length} items.</div>
      <div class="live-list">${list}</div>
    `;

    results.querySelectorAll(".live-item").forEach((itemEl) => {
      itemEl.addEventListener("click", () => {
        const line = Number(itemEl.dataset.line || "0");
        const column = Number(itemEl.dataset.column || "1");
        if (!editor || !line) {
          return;
        }
        if (highlightedLineHandle !== null) {
          editor.removeLineClass(highlightedLineHandle, "background", "live-highlight-line");
        }
        highlightedLineHandle = editor.addLineClass(
          line - 1,
          "background",
          "live-highlight-line"
        );
        editor.scrollIntoView({ line: line - 1, ch: Math.max(column - 1, 0) }, 80);
        editor.setCursor({ line: line - 1, ch: Math.max(column - 1, 0) });
        editor.focus();
      });
    });
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = getCodeValue();
    const codeBytes = getByteCount(code);
    if (codeBytes === 0) {
      setStatus("Paste a source snippet to scan.");
      return;
    }
    if (codeBytes > MAX_CODE_BYTES) {
      setStatus("Snippet too large. Keep it under 64 KB.");
      return;
    }

    const payload = {
      code,
      language: languageInput.value,
    };

    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = "Scanning...";
    }
    setStatus("Scanning with default patterns...");

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Scan failed");
      }
      renderItems(data.items || []);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Scan failed";
      setStatus(`${message}. Try again in a moment.`);
    } finally {
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.textContent = "Scan snippet";
      }
    }
  });

  languageInput.addEventListener("change", () => {
    if (editor) {
      editor.setOption("mode", modeForLanguage(languageInput.value));
    }
    updateCounterFromInput();
  });
  if (editor) {
    editor.on("change", updateCounterFromInput);
  } else {
    codeInput.addEventListener("input", updateCounterFromInput);
  }
  if (sampleButton) {
    sampleButton.addEventListener("click", () => {
      const sample = sampleSnippets[languageInput.value];
      if (sample) {
        setCodeValue(sample);
        updateCounterFromInput();
      }
    });
  }

  updateCounterFromInput();
};

initCopyButtons();
loadResults();
initLiveScan();
