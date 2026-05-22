(function () {
  const state = {
    busy: false,
    result: null,
  };

  const els = {
    upload: document.getElementById("apk-upload"),
    uploadTrigger: document.getElementById("upload-trigger"),
    status: document.getElementById("scan-status"),
    resultShell: document.getElementById("result-shell"),
    emptyState: document.getElementById("empty-state"),
    packageName: document.getElementById("package-name"),
    packageMeta: document.getElementById("package-meta"),
    findingTotalBadge: document.getElementById("finding-total-badge"),
    findingsList: document.getElementById("findings-list"),
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  function init() {
    if (!els.upload || !els.uploadTrigger) {
      return;
    }
    els.uploadTrigger.addEventListener("click", openFilePicker);
    els.upload.addEventListener("change", onUpload);
    updateUploadState();
    render();
  }

  function openFilePicker() {
    if (state.busy) {
      return;
    }
    els.upload.click();
  }

  async function onUpload(event) {
    const [file] = event.target.files || [];
    if (!file || state.busy) {
      return;
    }
    event.target.value = "";

    const formData = new FormData();
    formData.append("apk", file, file.name);

    setBusy(true, `Scanning ${file.name}...`);
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        body: formData,
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.error || "Scan failed");
      }
      state.result = payload.results?.[0] || null;
      setBusy(false, `Scan completed for ${file.name}`);
    } catch (error) {
      state.result = null;
      setBusy(false, `Scan failed: ${error.message}`);
    }
  }

  function setBusy(busy, label) {
    state.busy = busy;
    els.status.textContent = label;
    els.status.classList.toggle("busy", busy);
    updateUploadState();
    render();
  }

  function updateUploadState() {
    if (!els.upload || !els.uploadTrigger) {
      return;
    }
    els.upload.disabled = state.busy;
    els.uploadTrigger.disabled = state.busy;
    els.uploadTrigger.classList.toggle("upload-button-busy", state.busy);
    els.uploadTrigger.textContent = state.busy ? "Scanning..." : "Upload APK";
  }

  function render() {
    if (!state.result) {
      els.resultShell.classList.add("hidden");
      els.emptyState.classList.remove("hidden");
      return;
    }

    const findings = Array.isArray(state.result.findings) ? state.result.findings : [];
    els.emptyState.classList.add("hidden");
    els.resultShell.classList.remove("hidden");
    els.packageName.textContent = state.result.package_name || "Unknown package";
    els.packageMeta.textContent = buildHeaderMeta(state.result, findings);
    els.findingTotalBadge.textContent = findings.length === 1 ? "1 Finding" : `${findings.length} Findings`;
    renderFindings(findings);
  }

  function renderFindings(findings) {
    els.findingsList.innerHTML = "";

    if (!findings.length) {
      els.findingsList.appendChild(buildEmptyFindingsCard());
      return;
    }

    findings.forEach((finding) => {
      els.findingsList.appendChild(buildFindingCard(finding));
    });
  }

  function buildEmptyFindingsCard() {
    const card = document.createElement("article");
    card.className = "finding-card";
    card.innerHTML = `
      <div class="finding-head">
        <div class="finding-head-main">
          <span class="severity-dot"></span>
          <h2 class="finding-title">No findings reported by the current detector set</h2>
        </div>
        <span class="severity-pill severity-low">Clean</span>
      </div>
    `;
    return card;
  }

  function buildFindingCard(finding) {
    const extras = finding.extras || {};
    const evidenceBlocks = buildEvidenceBlocks(finding.evidence_blocks);
    const card = document.createElement("article");
    card.className = "finding-card";
    card.innerHTML = `
      <div class="finding-head">
        <div class="finding-head-main">
          <span class="severity-dot"></span>
          <h2 class="finding-title">${escapeHtml(finding.title)}</h2>
        </div>
        <span class="severity-pill ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
      </div>

      <div class="finding-summary">
        <div class="summary-row">
          <span class="summary-label">Affected Component</span>
          <div class="summary-text">${escapeHtml(finding.affected_component)}</div>
        </div>
        <div class="summary-row">
          <span class="summary-label">Issue</span>
          <div class="summary-text">${escapeHtml(finding.evidence)}</div>
        </div>
        <div class="summary-row">
          <span class="summary-label">Fix</span>
          <div class="summary-text">${escapeHtml(finding.remediation)}</div>
        </div>
      </div>

      <div class="meta-row">
        <span class="meta-chip">${escapeHtml(humanDetectorName(finding.detector))}</span>
        <span class="meta-chip">${escapeHtml(finding.confidence)} confidence</span>
        <span class="meta-chip">${escapeHtml(extras.component_exported === "true" ? "Exported" : "Internal")}</span>
        <span class="meta-chip">${escapeHtml(permissionChip(extras))}</span>
      </div>

      <div class="evidence-list">${evidenceBlocks}</div>
    `;
    return card;
  }

  function buildEvidenceBlocks(blocks) {
    if (!Array.isArray(blocks) || !blocks.length) {
      return `
        <section class="evidence-item">
          <div class="evidence-file">
            Found in file <strong>Evidence unavailable</strong>
          </div>
          <div class="code-panel">
            <div class="code-content">
              <div class="code-row">
                <span class="code-number"></span>
                <span class="code-text">The scan did not return nearby code for this finding.</span>
              </div>
            </div>
          </div>
        </section>
      `;
    }
    return blocks.map(renderSnippetBlock).join("");
  }

  function renderSnippetBlock(block) {
    const lines = Array.isArray(block.lines) ? block.lines : [];
    const file = String(block.file || "Trace");
    const range = formatLineRange(block.start_line, block.end_line);
    const renderedLines = lines
      .map((line) => {
        const lineNumber = line.number == null ? "" : escapeHtml(String(line.number));
        const lineText = escapeHtml(String(line.text || ""));
        const highlightClass = line.highlight ? " code-row-highlight" : "";
        return `
          <div class="code-row${highlightClass}">
            <span class="code-number">${lineNumber}</span>
            <span class="code-text">${lineText || "&nbsp;"}</span>
          </div>
        `;
      })
      .join("");

    return `
      <section class="evidence-item">
        <div class="evidence-file">
          Found in file <strong>${escapeHtml(file)}</strong>${range ? `<span class="evidence-range">${escapeHtml(range)}</span>` : ""}
        </div>
        <div class="code-panel">
          <div class="code-content">${renderedLines}</div>
        </div>
      </section>
    `;
  }

  function buildHeaderMeta(result, findings) {
    const apk = shortApkName(result.apk_path);
    const highCount = findings.filter((finding) => finding.severity === "HIGH").length;
    if (!findings.length) {
      return `${apk} - No findings`;
    }
    return `${apk} - ${highCount} high severity`;
  }

  function humanDetectorName(detector) {
    switch (detector) {
      case "intent_redirection":
        return "Intent Redirection";
      case "webview_misconfiguration":
        return "WebView Misconfiguration";
      case "insecure_content_provider":
        return "Insecure Content Provider";
      case "deep_link_abuse":
        return "Deep Link Abuse";
      default:
        return detector;
    }
  }

  function permissionChip(extras) {
    const level = extras.component_permission_level || "none";
    if (level === "none") {
      return "No permission gate";
    }
    return `${level} permission`;
  }

  function shortApkName(path) {
    const value = String(path || "");
    const parts = value.split(/[/\\]/);
    return parts[parts.length - 1] || value || "-";
  }

  function severityClass(severity) {
    const value = String(severity || "").toLowerCase();
    if (value === "high") {
      return "severity-high";
    }
    if (value === "medium") {
      return "severity-medium";
    }
    return "severity-low";
  }

  function formatLineRange(startLine, endLine) {
    if (typeof startLine !== "number") {
      return "";
    }
    if (typeof endLine !== "number" || endLine === startLine) {
      return `Line ${startLine}`;
    }
    return `Lines ${startLine}-${endLine}`;
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }
})();
