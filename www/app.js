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

initCopyButtons();
loadResults();
