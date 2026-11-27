
const API = "http://127.0.0.1:8000";

let evidenceRecords = [];
let latestIncident = null;


/* API REQUEST */

async function apiRequest(path, options = {}) {
    const response = await fetch(`${API}${path}`, options);

    if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return response.json();
}


/* SAFE HTML OUTPUT */

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}


function shorten(value, maxLength = 17) {
    const text = String(value ?? "Not available");

    return text.length <= maxLength
        ? text
        : text.slice(0, maxLength - 3) + "...";
}


/* LOAD DASHBOARD */

async function loadDashboard() {
    const connection = document.getElementById("connectionStatus");

    connection.textContent = "Connecting...";

    try {
        const data = await apiRequest(
            "/evidence/?limit=100&offset=0"
        );

        evidenceRecords = data.records || [];

        document.getElementById("totalEvidence").textContent =
            data.total;

        document.getElementById("investigationStatus").textContent =
            "Available";

        connection.textContent = "Connected";

        await loadIntegrity();
        renderEvidence();

    } catch (error) {
        connection.textContent = "Disconnected";

        document.getElementById("totalEvidence").textContent = "--";
        document.getElementById("verifiedEvidence").textContent = "--";
        document.getElementById("failedEvidence").textContent = "--";

        document.getElementById("investigationStatus").textContent =
            "Offline";

        document.getElementById("evidenceTable").innerHTML = `
            <tr>
                <td colspan="6">${escapeHTML(error.message)}</td>
            </tr>
        `;

        document.getElementById("integrityResults").textContent =
            "Unable to retrieve integrity results.";
    }
}


/* INTEGRITY VERIFICATION */

async function loadIntegrity() {
    let verified = 0;
    let failed = 0;

    const results = [];

    for (const item of evidenceRecords) {
        const evidence = item.evidence;

        try {
            const result = await apiRequest(
                `/evidence/${encodeURIComponent(evidence.evidence_id)}/verify`
            );

            if (result.integrity_valid) {
                verified++;
            } else {
                failed++;
            }

            results.push({
                id: evidence.evidence_id,
                status: result.status
            });

        } catch (error) {
            failed++;

            results.push({
                id: evidence.evidence_id,
                status: "VERIFICATION_ERROR"
            });
        }
    }

    document.getElementById("verifiedEvidence").textContent = verified;
    document.getElementById("failedEvidence").textContent = failed;

    document.getElementById("integrityResults").innerHTML =
        results.map(item => {
            const valid = item.status === "VERIFIED";

            return `
                <div class="integrity-item">
                    <span>${escapeHTML(item.id)}</span>
                    <strong class="${valid ? "verified" : "failed"}">
                        ${escapeHTML(item.status)}
                    </strong>
                </div>
            `;
        }).join("") || "No evidence records available.";
}


/* EVIDENCE TABLE */

function renderEvidence() {
    const table = document.getElementById("evidenceTable");

    if (!evidenceRecords.length) {
        table.innerHTML = `
            <tr>
                <td colspan="6">No evidence records found.</td>
            </tr>
        `;
        return;
    }

    table.innerHTML = evidenceRecords.map(item => {
        const evidence = item.evidence;

        return `
            <tr data-evidence-id="${escapeHTML(evidence.evidence_id)}">
                <td><code>${escapeHTML(evidence.evidence_id)}</code></td>
                <td>${escapeHTML(evidence.identity)}</td>
                <td>${escapeHTML(evidence.action)}</td>
                <td>${escapeHTML(evidence.authorization_status)}</td>
                <td>${escapeHTML(evidence.execution_status)}</td>
                <td>View Details</td>
            </tr>
        `;
    }).join("");
}


/* EVIDENCE DETAILS */

async function openEvidenceDetails(evidenceId) {
    const section = document.getElementById("evidenceDetails");
    const content = document.getElementById("evidenceDetailsContent");

    section.hidden = false;
    section.scrollIntoView({ behavior: "smooth" });

    content.textContent = "Loading evidence details...";

    try {
        const [record, verification] = await Promise.all([
            apiRequest(
                `/evidence/${encodeURIComponent(evidenceId)}`
            ),
            apiRequest(
                `/evidence/${encodeURIComponent(evidenceId)}/verify`
            )
        ]);

        const evidence = record.evidence;

        content.innerHTML = `
            <div class="details-grid">

                <div class="detail-card">
                    <p>Evidence ID</p>
                    <strong>${escapeHTML(evidence.evidence_id)}</strong>
                </div>

                <div class="detail-card">
                    <p>Identity</p>
                    <strong>${escapeHTML(evidence.identity)}</strong>
                </div>

                <div class="detail-card">
                    <p>Principal Type</p>
                    <strong>${escapeHTML(evidence.principal_type)}</strong>
                </div>

                <div class="detail-card">
                    <p>Action</p>
                    <strong>${escapeHTML(evidence.action)}</strong>
                </div>

                <div class="detail-card">
                    <p>Resource</p>
                    <strong>${escapeHTML(evidence.resource)}</strong>
                </div>

                <div class="detail-card">
                    <p>Authorization Status</p>
                    <strong>${escapeHTML(evidence.authorization_status)}</strong>
                </div>

                <div class="detail-card">
                    <p>Execution Status</p>
                    <strong>${escapeHTML(evidence.execution_status)}</strong>
                </div>

                <div class="detail-card">
                    <p>Observed Effect</p>
                    <strong>${escapeHTML(evidence.observed_effect || "Not provided")}</strong>
                </div>

                <div class="detail-card">
                    <p>Evidence Source</p>
                    <strong>${escapeHTML(evidence.source)}</strong>
                </div>

                <div class="detail-card">
                    <p>Timestamp</p>
                    <strong>${escapeHTML(evidence.timestamp)}</strong>
                </div>

                <div class="detail-card">
                    <p>Integrity Verification</p>
                    <strong class="${verification.integrity_valid ? "verified" : "failed"}">
                        ${escapeHTML(verification.status)}
                    </strong>
                </div>

                <div class="detail-card">
                    <p>SHA-256 Hash</p>
                    <div class="hash-value">
                        ${escapeHTML(record.sha256_hash)}
                    </div>
                </div>

            </div>
        `;

    } catch (error) {
        content.textContent =
            `Unable to retrieve evidence: ${error.message}`;
    }
}


function closeEvidenceDetails() {
    document.getElementById("evidenceDetails").hidden = true;
}


/* SEVERITY COUNTERS */

function updateSeverityCounters(findings) {
    document.getElementById("highCount").textContent =
        findings.filter(item => item.severity === "HIGH").length;

    document.getElementById("mediumCount").textContent =
        findings.filter(item => item.severity === "MEDIUM").length;

    document.getElementById("lowCount").textContent =
        findings.filter(item => item.severity === "LOW").length;
}


/* FINDINGS TABLE */

function renderFindings(findings) {
    const table = document.getElementById("findingsTable");

    if (!findings.length) {
        table.innerHTML = `
            <tr>
                <td colspan="4">No findings detected.</td>
            </tr>
        `;
        return;
    }

    table.innerHTML = findings.map(item => {
        const severity = ["HIGH", "MEDIUM", "LOW"].includes(
            item.severity
        ) ? item.severity : "LOW";

        return `
            <tr>
                <td>
                    <span class="severity-badge ${severity}">
                        ${escapeHTML(severity)}
                    </span>
                </td>
                <td>${escapeHTML(item.finding)}</td>
                <td><code>${escapeHTML(item.evidence_id)}</code></td>
                <td>${escapeHTML(item.description)}</td>
            </tr>
        `;
    }).join("");
}


/* INVESTIGATION TIMELINE */

function renderTimeline(timeline) {
    const table = document.getElementById("timelineTable");

    if (!timeline.length) {
        table.innerHTML = `
            <tr>
                <td colspan="6">No timeline events available.</td>
            </tr>
        `;
        return;
    }

    table.innerHTML = timeline.map(item => `
        <tr>
            <td>${escapeHTML(item.sequence)}</td>
            <td>${escapeHTML(item.timestamp)}</td>
            <td>${escapeHTML(item.identity)}</td>
            <td>${escapeHTML(item.action)}</td>
            <td>${escapeHTML(item.authorization_status)}</td>
            <td>${escapeHTML(item.execution_status)}</td>
        </tr>
    `).join("");
}


/* MULTI-EVENT RELATIONSHIP GRAPH */

function renderRelationshipGraph(result) {
    const container = document.getElementById("relationshipGraph");
    const details = document.getElementById("graphNodeDetails");

    const timeline = result.timeline || [];
    const findings = result.findings || [];

    if (!timeline.length) {
        container.innerHTML = `
            <p class="graph-empty">
                No events available to visualize.
            </p>
        `;

        details.textContent = "No graph nodes available.";
        return;
    }

    const nodeTypes = [
        {
            key: "identity",
            label: "IDENTITY",
            color: "#60a5fa",
            background: "#142b46"
        },
        {
            key: "authorization_status",
            label: "AUTHORIZATION",
            color: "#f5bd55",
            background: "#382d19"
        },
        {
            key: "action",
            label: "ACTION",
            color: "#35d5d0",
            background: "#123437"
        },
        {
            key: "execution_status",
            label: "EXECUTION",
            color: "#ff8b5c",
            background: "#3b251e"
        },
        {
            key: "observed_effect",
            label: "OBSERVED EFFECT",
            color: "#a78bfa",
            background: "#292343"
        },
        {
            key: "finding",
            label: "SECURITY FINDING",
            color: "#ff6378",
            background: "#3a1926"
        }
    ];

    const svgWidth = 900;
    const nodeWidth = 125;
    const nodeHeight = 78;
    const startX = 10;
    const gap = 25;
    const rowHeight = 145;
    const startY = 35;

    const svgHeight = Math.max(
        180,
        startY + timeline.length * rowHeight
    );

    const allNodes = [];
    let svg = `
        <svg viewBox="0 0 ${svgWidth} ${svgHeight}"
             xmlns="http://www.w3.org/2000/svg"
             role="img"
             aria-label="Multi-event evidence relationship graph">
    `;

    timeline.forEach((event, rowIndex) => {
        const matchingFinding = findings.find(
            item => item.evidence_id === event.evidence_id
        );

        const y = startY + rowIndex * rowHeight;

        nodeTypes.forEach((type, nodeIndex) => {
            const x = startX + nodeIndex * (nodeWidth + gap);

            const value = type.key === "finding"
                ? (matchingFinding
                    ? matchingFinding.finding
                    : "No finding")
                : (event[type.key] || "Not provided");

            const node = {
                row: rowIndex + 1,
                type: type.label,
                value: String(value),
                evidenceId: event.evidence_id,
                timestamp: event.timestamp,
                identity: event.identity,
                resource: event.resource,
                source: event.source,
                severity: matchingFinding?.severity || "NONE",
                description: matchingFinding?.description ||
                    "No finding associated with this event."
            };

            const nodeId = allNodes.length;
            allNodes.push(node);

            if (nodeIndex > 0) {
                svg += `
                    <path class="graph-edge"
                        d="M ${x - gap + nodeWidth} ${y + nodeHeight / 2}
                           L ${x} ${y + nodeHeight / 2}" />
                `;
            }

            svg += `
                <g class="graph-node"
                   data-node-index="${nodeId}"
                   tabindex="0"
                   role="button"
                   aria-label="${escapeHTML(type.label)}: ${escapeHTML(value)}">

                    <title>${escapeHTML(value)}</title>

                    <rect x="${x}" y="${y}"
                          width="${nodeWidth}"
                          height="${nodeHeight}"
                          rx="9"
                          fill="${type.background}"
                          stroke="${type.color}" />

                    <text x="${x + nodeWidth / 2}"
                          y="${y + 25}"
                          text-anchor="middle"
                          font-size="10"
                          font-weight="700"
                          fill="${type.color}">
                        ${type.label}
                    </text>

                    <text x="${x + nodeWidth / 2}"
                          y="${y + 49}"
                          text-anchor="middle"
                          font-size="10">
                        ${escapeHTML(shorten(value))}
                    </text>
                </g>
            `;
        });

        if (rowIndex < timeline.length - 1) {
            const dividerY = y + nodeHeight + 34;

            svg += `
                <line x1="5" y1="${dividerY}"
                      x2="895" y2="${dividerY}"
                      stroke="#26364e"
                      stroke-dasharray="5 5" />
            `;
        }
    });

    svg += "</svg>";

    container.innerHTML = svg;

    details.textContent =
        `${timeline.length} events visualized. Select any node to inspect its evidence.`;

    container.onclick = event => {
        const nodeElement = event.target.closest("[data-node-index]");

        if (!nodeElement) return;

        selectGraphNode(
            Number(nodeElement.dataset.nodeIndex),
            allNodes,
            container,
            details
        );
    };

    container.onkeydown = event => {
        if (event.key !== "Enter" && event.key !== " ") return;

        const nodeElement = event.target.closest("[data-node-index]");

        if (!nodeElement) return;

        event.preventDefault();

        selectGraphNode(
            Number(nodeElement.dataset.nodeIndex),
            allNodes,
            container,
            details
        );
    };
}


/* GRAPH NODE INSPECTION */

function selectGraphNode(index, nodes, container, details) {
    const node = nodes[index];

    if (!node) return;

    container.querySelectorAll(".graph-node").forEach(element => {
        element.classList.remove("selected");
    });

    const selected = container.querySelector(
        `[data-node-index="${index}"]`
    );

    if (selected) {
        selected.classList.add("selected");
    }

    details.innerHTML = `
        <strong>${escapeHTML(node.type)}</strong>
        <p>Value: ${escapeHTML(node.value)}</p>
        <p>Event row: ${escapeHTML(node.row)}</p>
        <p>Identity: ${escapeHTML(node.identity)}</p>
        <p>Resource: ${escapeHTML(node.resource)}</p>
        <p>Evidence ID: ${escapeHTML(node.evidenceId)}</p>
        <p>Timestamp: ${escapeHTML(node.timestamp)}</p>
        <p>Source: ${escapeHTML(node.source)}</p>
        <p>Finding severity: ${escapeHTML(node.severity)}</p>
        <p>Description: ${escapeHTML(node.description)}</p>
    `;
}


/* DISPLAY INCIDENT RESULT */

function displayIncident(result) {
    latestIncident = result;

    const findings = result.findings || [];
    const timeline = result.timeline || [];

    updateSeverityCounters(findings);
    renderFindings(findings);
    renderTimeline(timeline);
    renderRelationshipGraph(result);

    document.getElementById("incidentStatus").textContent =
        result.status || "Unknown";

    document.getElementById("incidentMessage").textContent =
        `${result.total_events} events processed. ${findings.length} findings detected.`;

    document.getElementById("incidentResults").textContent =
        JSON.stringify(result, null, 2);
}


/* CREATE THREE SYNTHETIC EVENTS */

function createMultiEventPayload() {
    const now = Date.now();

    const timestamp = secondsAgo =>
        new Date(now - secondsAgo * 1000).toISOString();

    const identity = "multi-event-test-user";
    const resource = "AEGIS-X synthetic restricted file";

    return {
        records: [

            {
                identity,
                principal_type: "human",
                action: "User login",
                resource: "AEGIS-X test application",
                authorization_status: "authorized",
                execution_status: "success",
                observed_effect: "Synthetic test session created",
                source: "synthetic-lab",
                timestamp: timestamp(120)
            },

            {
                identity,
                principal_type: "human",
                action: "Restricted file authorization check",
                resource,
                authorization_status: "denied",
                execution_status: "blocked",
                observed_effect: "Access request rejected",
                source: "synthetic-lab",
                timestamp: timestamp(60)
            },

            {
                identity,
                principal_type: "human",
                action: "Restricted file access",
                resource,
                authorization_status: "denied",
                execution_status: "success",
                observed_effect: "Synthetic file access recorded",
                source: "synthetic-lab",
                timestamp: timestamp(0)
            }

        ]
    };
}


/* RUN MULTI-EVENT INVESTIGATION */

async function runIncidentTest() {
    const button = document.getElementById("incidentTestButton");
    const message = document.getElementById("incidentMessage");

    button.disabled = true;
    button.textContent = "Investigating...";

    message.textContent =
        "Submitting three synthetic events for reconstruction...";

    try {
        const payload = createMultiEventPayload();

        const result = await apiRequest(
            "/incidents/reconstruct",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
            }
        );

        displayIncident(result);

    } catch (error) {
        message.textContent =
            `Investigation failed: ${error.message}`;

    } finally {
        button.disabled = false;
        button.textContent = "Run Test Investigation";
    }
}


/* EVENT LISTENERS */

document.getElementById("refreshButton")
    .addEventListener("click", loadDashboard);

document.getElementById("closeDetailsButton")
    .addEventListener("click", closeEvidenceDetails);

document.getElementById("incidentTestButton")
    .addEventListener("click", runIncidentTest);

document.getElementById("evidenceTable")
    .addEventListener("click", event => {
        const row = event.target.closest("tr[data-evidence-id]");

        if (row) {
            openEvidenceDetails(row.dataset.evidenceId);
        }
    });


/* INITIALIZE */

loadDashboard();
