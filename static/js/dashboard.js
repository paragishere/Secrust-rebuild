
"use strict";

/* =========================================================
   SECRUST WEBSHIELD — DASHBOARD
   Websites, Logs Explorer, Alerts, Role-based UI
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {
    const $ = (id) => document.getElementById(id);

    const result = $("result");
    const websiteList = $("websiteList");
    const createButton = $("createButton");
    const websiteForm = $("websiteForm");

    const logsTableBody = $("logsTableBody");
    const logsMessage = $("logsMessage");
    const paginationInfo = $("paginationInfo");
    const previousPageButton = $("previousPage");
    const nextPageButton = $("nextPage");

    const alertsTableBody = $("alertsTableBody");
    const alertsMessage = $("alertsMessage");
    const alertsPaginationInfo = $("alertsPaginationInfo");
    const previousAlertsPage = $("previousAlertsPage");
    const nextAlertsPage = $("nextAlertsPage");

    const PAGE_SIZE = 20;
    const ALERT_PAGE_SIZE = 20;

    let currentOffset = 0;
    let alertOffset = 0;
    let logsLoading = false;
    let alertsLoading = false;
    let selectedAlertID = "";
    let selectedAlertStatus = "";

    // Role must be supplied by the authenticated dashboard template.
    const currentRole = String(
        document.body?.dataset?.userRole || ""
    ).trim().toUpperCase();

    const canManageWebsites = ["SUPER_ADMIN", "MANAGER"].includes(currentRole);
    const canManageAlerts = ["SUPER_ADMIN", "MANAGER", "ANALYST"].includes(currentRole);

    /* ---------------- Shared helpers ---------------- */

    function getCookie(name) {
        const prefix = name + "=";
        const item = document.cookie
            .split("; ")
            .find((cookie) => cookie.startsWith(prefix));

        if (!item) return "";

        try {
            return decodeURIComponent(item.substring(prefix.length));
        } catch {
            return "";
        }
    }

    async function readJSON(response) {
        const contentType = response.headers.get("content-type") || "";

        if (!contentType.includes("application/json")) return {};

        try {
            return await response.json();
        } catch {
            return {};
        }
    }

    function showMessage(message, isError = false) {
        if (!result) return;

        result.replaceChildren();

        const paragraph = document.createElement("p");
        paragraph.textContent = message;
        paragraph.className = isError ? "error" : "success";

        result.appendChild(paragraph);
    }

    function setMessage(element, message, type = "muted") {
        if (!element) return;

        element.textContent = message;
        element.className = type;
    }

    function setDisabled(element, disabled) {
        if (element) element.disabled = disabled;
    }

    function formatTimestamp(value) {
        if (!value) return "—";

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) return String(value);

        return date.toISOString().replace("T", " ").replace("Z", " UTC");
    }

    function createCell(value, className = "") {
        const cell = document.createElement("td");

        cell.textContent =
            value === null || value === undefined || value === ""
                ? "—"
                : String(value);

        if (className) cell.className = className;

        return cell;
    }

    function severityClass(value) {
        const severity = String(value || "").toLowerCase();

        return ["info", "low", "medium", "high", "critical"].includes(severity)
            ? "severity-" + severity
            : "";
    }

    function statusClass(value) {
        const status = Number(value);

        if (status >= 200 && status < 300) return "status-success";
        if (status >= 300 && status < 400) return "status-warning";
        if (status >= 400 && status <= 599) return "status-error";

        return "";
    }

    function showSessionExpired(element) {
        setMessage(
            element,
            "Your session may have expired. Please log in again.",
            "error"
        );
    }

    /* ---------------- Role-based interface ---------------- */

    function applyRoleBasedUI() {
        const registration = $("websiteRegistration");
        if (registration && !canManageWebsites) registration.hidden = true;

        const organizationLink = $("organizationLink");
        if (
            organizationLink &&
            !["SUPER_ADMIN", "MANAGER", "ANALYST", "VIEWER"].includes(currentRole)
        ) {
            organizationLink.hidden = true;
        }

        const alertActions = $("alertActions");
        if (alertActions && !canManageAlerts) alertActions.hidden = true;

        // If role was not supplied, hide privileged UI by default.
        if (!currentRole && registration) registration.hidden = true;
        if (!currentRole && alertActions) alertActions.hidden = true;
    }

    applyRoleBasedUI();

    /* ---------------- Website registration ---------------- */

    function showAPIKey(domain, apiKey) {
        if (!result) return;

        result.replaceChildren();

        const heading = document.createElement("p");
        heading.textContent = "Website created: " + domain;
        result.appendChild(heading);

        const warning = document.createElement("p");
        warning.className = "muted";
        warning.textContent =
            "Copy this API key now and store it securely. It may not be retrievable again.";
        result.appendChild(warning);

        const keyInput = document.createElement("input");
        keyInput.type = "password";
        keyInput.readOnly = true;
        keyInput.autocomplete = "off";
        keyInput.value = apiKey;
        keyInput.setAttribute("aria-label", "Generated API key");
        result.appendChild(keyInput);

        const revealButton = document.createElement("button");
        revealButton.type = "button";
        revealButton.textContent = "Show key";

        revealButton.addEventListener("click", () => {
            const reveal = keyInput.type === "password";
            keyInput.type = reveal ? "text" : "password";
            revealButton.textContent = reveal ? "Hide key" : "Show key";
        });

        result.appendChild(revealButton);

        const copyButton = document.createElement("button");
        copyButton.type = "button";
        copyButton.textContent = "Copy API key";

        copyButton.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(apiKey);
                copyButton.textContent = "Copied";
            } catch {
                keyInput.type = "text";
                keyInput.focus();
                keyInput.select();
                copyButton.textContent = "Select key and copy";
            }
        });

        result.appendChild(copyButton);
    }

    if (websiteForm) {
        websiteForm.addEventListener("submit", async (event) => {
            event.preventDefault();

            if (!canManageWebsites) {
                showMessage("Your role cannot register websites.", true);
                return;
            }

            const domain = $("domain")?.value?.trim() || "";
            const csrfToken = getCookie("secrust_csrf");

            if (!domain) {
                showMessage("Please enter a website domain.", true);
                return;
            }

            if (!csrfToken) {
                showMessage(
                    "CSRF token is missing. Refresh the dashboard and try again.",
                    true
                );
                return;
            }

            setDisabled(createButton, true);
            showMessage("Creating website...");

            try {
                const response = await fetch("/api/websites", {
                    method: "POST",
                    credentials: "same-origin",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "X-CSRF-Token": csrfToken
                    },
                    body: JSON.stringify({ domain })
                });

                const data = await readJSON(response);

                if (response.redirected) {
                    showSessionExpired(result);
                    return;
                }

                if (!response.ok) {
                    showMessage(
                        data.error || `Website creation failed (HTTP ${response.status}).`,
                        true
                    );
                    return;
                }

                if (!data.website || !data.api_key) {
                    showMessage(
                        "Website response was incomplete. Check the server logs.",
                        true
                    );
                    return;
                }

                showAPIKey(data.website.domain || domain, data.api_key);

                if ($("domain")) $("domain").value = "";

                await loadWebsites();
            } catch (error) {
                console.error("Website registration error:", error);
                showMessage("Request failed. Check that the server is running.", true);
            } finally {
                setDisabled(createButton, false);
            }
        });
    }

    async function loadWebsites() {
        if (!websiteList) return;

        websiteList.textContent = "Loading websites...";

        try {
            const response = await fetch("/api/websites", {
                method: "GET",
                credentials: "same-origin",
                headers: { "Accept": "application/json" }
            });

            const data = await readJSON(response);

            if (response.redirected) {
                websiteList.textContent = "Session expired. Please log in again.";
                return;
            }

            if (!response.ok) {
                websiteList.textContent =
                    data.error || `Unable to load websites (HTTP ${response.status}).`;
                return;
            }

            const websites = Array.isArray(data.websites)
                ? data.websites
                : [];

            websiteList.replaceChildren();

            if (websites.length === 0) {
                websiteList.textContent = "No websites registered yet.";
                return;
            }

            const list = document.createElement("ul");

            websites.forEach((website) => {
                const item = document.createElement("li");
                item.textContent =
                    `${website.domain || "Unknown domain"} — ${website.status || "unknown"}`;
                list.appendChild(item);
            });

            websiteList.appendChild(list);
        } catch (error) {
            console.error("Load websites error:", error);
            websiteList.textContent =
                "Unable to load websites. Check the server connection.";
        }
    }

    $("refreshWebsites")?.addEventListener("click", loadWebsites);

    /* ---------------- Logs Explorer ---------------- */

    function renderLogs(logs) {
        if (!logsTableBody) return;

        logsTableBody.replaceChildren();

        if (logs.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 7;
            cell.className = "empty-state";
            cell.textContent = "No logs found for this page.";

            row.appendChild(cell);
            logsTableBody.appendChild(row);
            return;
        }

        logs.forEach((log) => {
            const row = document.createElement("tr");

            row.appendChild(createCell(formatTimestamp(log.CreatedAt)));

            const severityCell = document.createElement("td");
            const severityBadge = document.createElement("span");

            severityBadge.className = "badge " + severityClass(log.Severity);
            severityBadge.textContent = log.Severity || "unknown";

            severityCell.appendChild(severityBadge);
            row.appendChild(severityCell);

            row.appendChild(createCell(log.EventType));
            row.appendChild(createCell(log.Method));
            row.appendChild(createCell(log.Path, "path-cell"));
            row.appendChild(createCell(log.Status, statusClass(log.Status)));
            row.appendChild(createCell(log.IP));

            logsTableBody.appendChild(row);
        });
    }

    async function loadLogs() {
        if (logsLoading || !logsTableBody) return;

        logsLoading = true;

        const refreshButton = $("refreshLogs");
        const applyButton = $("applyFilters");

        setDisabled(refreshButton, true);
        setDisabled(applyButton, true);
        setDisabled(previousPageButton, true);
        setDisabled(nextPageButton, true);

        setMessage(logsMessage, "Loading logs...");

        const params = new URLSearchParams({
            limit: String(PAGE_SIZE),
            offset: String(currentOffset)
        });

        const search = $("logSearch")?.value?.trim() || "";
        const severity = $("severityFilter")?.value || "";
        const status = $("statusFilter")?.value || "";
        const eventType = $("eventTypeFilter")?.value?.trim() || "";

        if (search) params.set("search", search);
        if (severity) params.set("severity", severity);
        if (status) params.set("status", status);
        if (eventType) params.set("event_type", eventType);

        try {
            const response = await fetch(`/api/logs?${params.toString()}`, {
                method: "GET",
                credentials: "same-origin",
                headers: { "Accept": "application/json" }
            });

            const data = await readJSON(response);

            if (response.redirected) {
                showSessionExpired(logsMessage);
                renderLogs([]);
                return;
            }

            if (!response.ok) {
                setMessage(
                    logsMessage,
                    data.error || `Unable to load logs (HTTP ${response.status}).`,
                    "error"
                );
                renderLogs([]);
                return;
            }

            if (!Array.isArray(data.logs)) {
                setMessage(logsMessage, "Unexpected response from logs API.", "error");
                renderLogs([]);
                return;
            }

            renderLogs(data.logs);

            setMessage(
                logsMessage,
                data.logs.length
                    ? `Loaded ${data.logs.length} log(s).`
                    : "No logs match the selected filters.",
                data.logs.length ? "success" : "muted"
            );

            const pageNumber = Math.floor(currentOffset / PAGE_SIZE) + 1;
            if (paginationInfo) paginationInfo.textContent = `Page ${pageNumber}`;

            setDisabled(previousPageButton, currentOffset === 0);
            setDisabled(nextPageButton, data.logs.length < PAGE_SIZE);
        } catch (error) {
            console.error("Load logs error:", error);
            setMessage(logsMessage, "Unable to connect to the logs API.", "error");
            renderLogs([]);
        } finally {
            logsLoading = false;
            setDisabled(refreshButton, false);
            setDisabled(applyButton, false);
        }
    }

    $("applyFilters")?.addEventListener("click", () => {
        currentOffset = 0;
        loadLogs();
    });

    $("clearFilters")?.addEventListener("click", () => {
        ["logSearch", "severityFilter", "statusFilter", "eventTypeFilter"]
            .forEach((id) => {
                if ($(id)) $(id).value = "";
            });

        currentOffset = 0;
        loadLogs();
    });

    ["logSearch", "eventTypeFilter"].forEach((id) => {
        $(id)?.addEventListener("keydown", (event) => {
            if (event.key === "Enter") {
                event.preventDefault();
                currentOffset = 0;
                loadLogs();
            }
        });
    });

    $("refreshLogs")?.addEventListener("click", loadLogs);

    previousPageButton?.addEventListener("click", () => {
        if (currentOffset >= PAGE_SIZE) {
            currentOffset -= PAGE_SIZE;
            loadLogs();
        }
    });

    nextPageButton?.addEventListener("click", () => {
        currentOffset += PAGE_SIZE;
        loadLogs();
    });

    /* ---------------- Alert Management ---------------- */

    function normalizeAlert(raw) {
        if (!raw || typeof raw !== "object") return null;

        const pick = (...keys) => {
            for (const key of keys) {
                if (raw[key] !== undefined) return raw[key];
            }
            return undefined;
        };

        return {
            id: pick("id", "ID"),
            organization_id: pick("organization_id", "OrganizationID"),
            website_id: pick("website_id", "WebsiteID"),
            severity: pick("severity", "Severity"),
            type: pick("type", "Type"),
            message: pick("message", "Message"),
            ip: pick("ip", "IP"),
            status: pick("status", "Status"),
            rule_key: pick("rule_key", "RuleKey"),
            details: pick("details", "Details"),
            created_at: pick("created_at", "CreatedAt"),
            acknowledged_by: pick("acknowledged_by", "AcknowledgedBy"),
            acknowledged_at: pick("acknowledged_at", "AcknowledgedAt"),
            resolved_by: pick("resolved_by", "ResolvedBy"),
            resolved_at: pick("resolved_at", "ResolvedAt")
        };
    }

    function alertStatusClass(status) {
        const value = String(status || "").toLowerCase();

        return ["open", "acknowledged", "resolved"].includes(value)
            ? "alert-status alert-" + value
            : "alert-status";
    }

    function addAlertDetail(parent, label, value) {
        const wrapper = document.createElement("div");
        wrapper.className = "alert-detail";

        const heading = document.createElement("strong");
        heading.textContent = label;

        const content = document.createElement("span");
        content.textContent =
            value === null || value === undefined || value === ""
                ? "—"
                : String(value);

        wrapper.append(heading, content);
        parent.appendChild(wrapper);
    }

    function renderAlertDetails(alert) {
        const container = $("alertDetails");
        const panel = $("alertDetailsPanel");
        const actions = $("alertActions");

        if (!container || !panel) return;

        container.replaceChildren();
        panel.hidden = false;

        const grid = document.createElement("div");
        grid.className = "alert-details-grid";

        addAlertDetail(grid, "Alert ID", alert.id);
        addAlertDetail(grid, "Organization", alert.organization_id);
        addAlertDetail(grid, "Website ID", alert.website_id);
        addAlertDetail(grid, "Severity", alert.severity);
        addAlertDetail(grid, "Type", alert.type);
        addAlertDetail(grid, "Rule Key", alert.rule_key);
        addAlertDetail(grid, "Source IP", alert.ip);
        addAlertDetail(grid, "Status", alert.status);
        addAlertDetail(grid, "Created (UTC)", formatTimestamp(alert.created_at));
        addAlertDetail(grid, "Acknowledged By", alert.acknowledged_by);
        addAlertDetail(grid, "Acknowledged At (UTC)", formatTimestamp(alert.acknowledged_at));
        addAlertDetail(grid, "Resolved By", alert.resolved_by);
        addAlertDetail(grid, "Resolved At (UTC)", formatTimestamp(alert.resolved_at));

        container.appendChild(grid);

        const messageHeading = document.createElement("h3");
        messageHeading.textContent = "Alert Message";
        container.appendChild(messageHeading);

        const message = document.createElement("p");
        message.textContent = alert.message || "No message available.";
        container.appendChild(message);

        const detailsHeading = document.createElement("h3");
        detailsHeading.textContent = "Detection Details";
        container.appendChild(detailsHeading);

        const details = document.createElement("pre");
        details.textContent = JSON.stringify(alert.details || {}, null, 2);
        container.appendChild(details);

        setMessage($("alertDetailsMessage"), "Viewing alert " + (alert.id || ""));

        selectedAlertID = alert.id || "";
        selectedAlertStatus = String(alert.status || "").toLowerCase();

        const canActOnAlert =
            canManageAlerts &&
            ["open", "acknowledged"].includes(selectedAlertStatus);

        if (actions) actions.hidden = !canActOnAlert;

        const acknowledgeButton = $("acknowledgeAlert");
        const resolveButton = $("resolveAlert");

        if (acknowledgeButton) {
            acknowledgeButton.hidden =
                !canActOnAlert || selectedAlertStatus !== "open";
        }

        if (resolveButton) {
            resolveButton.hidden = !canActOnAlert;
        }
    }

    async function openAlertDetails(alertID) {
        const panel = $("alertDetailsPanel");
        const container = $("alertDetails");
        const message = $("alertDetailsMessage");

        if (!panel || !container || !message) return;

        panel.hidden = false;
        container.replaceChildren();
        setMessage(message, "Loading alert details...");

        try {
            const response = await fetch(
                "/api/alerts/" + encodeURIComponent(alertID),
                {
                    method: "GET",
                    credentials: "same-origin",
                    headers: { "Accept": "application/json" }
                }
            );

            const data = await readJSON(response);

            if (response.redirected) {
                showSessionExpired(message);
                return;
            }

            if (!response.ok) {
                setMessage(
                    message,
                    data.error || `Unable to load alert (HTTP ${response.status}).`,
                    "error"
                );
                return;
            }

            // API may return {alert: {...}} or the alert directly.
            const rawAlert = data.alert || data.Alert || data;

            if (!rawAlert || typeof rawAlert !== "object") {
                setMessage(message, "Unexpected response from alert API.", "error");
                return;
            }

            const alert = normalizeAlert(rawAlert);

            if (!alert || alert.id === undefined || alert.id === null) {
                setMessage(message, "Alert ID is missing in the API response.", "error");
                return;
            }

            renderAlertDetails(alert);
        } catch (error) {
            console.error("Alert details error:", error);
            setMessage(message, "Unable to connect to the alert API.", "error");
        }
    }

    function renderAlerts(alerts) {
        if (!alertsTableBody) return;

        alertsTableBody.replaceChildren();

        if (alerts.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 6;
            cell.className = "empty-state";
            cell.textContent = "No alerts found.";

            row.appendChild(cell);
            alertsTableBody.appendChild(row);
            return;
        }

        alerts.forEach((alert) => {
            const row = document.createElement("tr");

            row.className = "alert-row";
            row.tabIndex = 0;
            row.setAttribute("role", "button");
            row.setAttribute(
                "aria-label",
                "View alert: " + (alert.message || alert.id || "Security alert")
            );

            if (String(alert.id) === String(selectedAlertID)) {
                row.classList.add("selected");
            }

            row.appendChild(createCell(formatTimestamp(alert.created_at)));

            const severityCell = document.createElement("td");
            const severityBadge = document.createElement("span");

            severityBadge.className = "badge " + severityClass(alert.severity);
            severityBadge.textContent = alert.severity || "unknown";

            severityCell.appendChild(severityBadge);
            row.appendChild(severityCell);

            row.appendChild(createCell(alert.message || alert.type));
            row.appendChild(createCell(alert.ip));

            const statusCell = document.createElement("td");
            const statusBadge = document.createElement("span");

            statusBadge.className = alertStatusClass(alert.status);
            statusBadge.textContent = alert.status || "unknown";

            statusCell.appendChild(statusBadge);
            row.appendChild(statusCell);

            const actionCell = document.createElement("td");
            const viewButton = document.createElement("button");

            viewButton.type = "button";
            viewButton.textContent = "View Details";

            viewButton.addEventListener("click", (event) => {
                event.stopPropagation();
                openAlertDetails(alert.id);
            });

            actionCell.appendChild(viewButton);
            row.appendChild(actionCell);

            row.addEventListener("click", () => openAlertDetails(alert.id));

            row.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    openAlertDetails(alert.id);
                }
            });

            alertsTableBody.appendChild(row);
        });
    }

    async function loadAlerts() {
        if (alertsLoading || !alertsTableBody) return;

        alertsLoading = true;

        const refreshButton = $("refreshAlerts");
        const applyButton = $("applyAlertFilters");

        setDisabled(refreshButton, true);
        setDisabled(applyButton, true);
        setDisabled(previousAlertsPage, true);
        setDisabled(nextAlertsPage, true);

        setMessage(alertsMessage, "Loading alerts...");

        const params = new URLSearchParams({
            limit: String(ALERT_PAGE_SIZE),
            offset: String(alertOffset)
        });

        const status = $("alertStatusFilter")?.value || "";
        if (status) params.set("status", status);

        try {
            const response = await fetch("/api/alerts?" + params.toString(), {
                method: "GET",
                credentials: "same-origin",
                headers: { "Accept": "application/json" }
            });

            const data = await readJSON(response);

            if (response.redirected) {
                showSessionExpired(alertsMessage);
                renderAlerts([]);
                return;
            }

            if (!response.ok) {
                setMessage(
                    alertsMessage,
                    data.error || `Unable to load alerts (HTTP ${response.status}).`,
                    "error"
                );
                renderAlerts([]);
                return;
            }

            const rawAlerts = Array.isArray(data.alerts) ? data.alerts
                : Array.isArray(data.Alerts) ? data.Alerts
                : Array.isArray(data.data) ? data.data
                : null;

            if (!rawAlerts) {
                setMessage(alertsMessage, "Unexpected response from alerts API.", "error");
                renderAlerts([]);
                return;
            }

            const alerts = rawAlerts
                .map(normalizeAlert)
                .filter((alert) => alert && alert.id !== undefined && alert.id !== null);

            renderAlerts(alerts);

            setMessage(
                alertsMessage,
                alerts.length
                    ? `Loaded ${alerts.length} alert(s).`
                    : "No alerts match the selected filters.",
                alerts.length ? "success" : "muted"
            );

            const pageNumber = Math.floor(alertOffset / ALERT_PAGE_SIZE) + 1;
            if (alertsPaginationInfo) {
                alertsPaginationInfo.textContent = "Page " + pageNumber;
            }

            setDisabled(previousAlertsPage, alertOffset === 0);
            setDisabled(nextAlertsPage, alerts.length < ALERT_PAGE_SIZE);
        } catch (error) {
            console.error("Load alerts error:", error);
            setMessage(alertsMessage, "Unable to connect to the alerts API.", "error");
            renderAlerts([]);
        } finally {
            alertsLoading = false;
            setDisabled(refreshButton, false);
            setDisabled(applyButton, false);
        }
    }

    async function updateAlertStatus(action) {
        if (!selectedAlertID) return;

        if (!canManageAlerts) {
            setMessage($("alertDetailsMessage"), "Your role cannot update alerts.", "error");
            return;
        }

        if (!["acknowledge", "resolve"].includes(action)) {
            setMessage($("alertDetailsMessage"), "Invalid alert action.", "error");
            return;
        }

        const csrfToken = getCookie("secrust_csrf");

        if (!csrfToken) {
            setMessage(
                $("alertDetailsMessage"),
                "CSRF token is missing. Refresh the dashboard and try again.",
                "error"
            );
            return;
        }

        const acknowledgeButton = $("acknowledgeAlert");
        const resolveButton = $("resolveAlert");

        setDisabled(acknowledgeButton, true);
        setDisabled(resolveButton, true);

        const alertID = selectedAlertID;

        try {
            const response = await fetch(
                "/api/alerts/" + encodeURIComponent(alertID) + "/" + action,
                {
                    method: "PATCH",
                    credentials: "same-origin",
                    headers: {
                        "Accept": "application/json",
                        "X-CSRF-Token": csrfToken
                    }
                }
            );

            const data = await readJSON(response);

            if (response.redirected) {
                showSessionExpired($("alertDetailsMessage"));
                return;
            }

            if (!response.ok) {
                setMessage(
                    $("alertDetailsMessage"),
                    data.error || `Action failed (HTTP ${response.status}).`,
                    "error"
                );
                return;
            }

            setMessage(
                $("alertDetailsMessage"),
                action === "acknowledge" ? "Alert acknowledged." : "Alert resolved.",
                "success"
            );

            await loadAlerts();
            await openAlertDetails(alertID);
        } catch (error) {
            console.error("Update alert error:", error);
            setMessage(
                $("alertDetailsMessage"),
                "Unable to update alert status.",
                "error"
            );
        } finally {
            setDisabled(acknowledgeButton, false);
            setDisabled(resolveButton, false);
        }
    }

    $("refreshAlerts")?.addEventListener("click", loadAlerts);

    $("applyAlertFilters")?.addEventListener("click", () => {
        alertOffset = 0;
        loadAlerts();
    });

    $("clearAlertFilters")?.addEventListener("click", () => {
        if ($("alertStatusFilter")) $("alertStatusFilter").value = "";
        alertOffset = 0;
        loadAlerts();
    });

    previousAlertsPage?.addEventListener("click", () => {
        if (alertOffset >= ALERT_PAGE_SIZE) {
            alertOffset -= ALERT_PAGE_SIZE;
            loadAlerts();
        }
    });

    nextAlertsPage?.addEventListener("click", () => {
        alertOffset += ALERT_PAGE_SIZE;
        loadAlerts();
    });

    $("acknowledgeAlert")?.addEventListener("click", () => {
        updateAlertStatus("acknowledge");
    });

    $("resolveAlert")?.addEventListener("click", () => {
        updateAlertStatus("resolve");
    });

    $("closeAlertDetails")?.addEventListener("click", () => {
        const panel = $("alertDetailsPanel");
        if (panel) panel.hidden = true;
    });

    /* ---------------- Endpoint Monitoring ---------------- */

    const endpointTableBody = $("endpointsTableBody");
    const endpointEventsBody = $("endpointEventsTableBody");
    const ENDPOINT_EVENT_PAGE_SIZE = 50;

    let endpointHosts = [];
    let selectedEndpointID = "";
    let endpointEventOffset = 0;
    let endpointEventTotal = 0;
    let endpointHostsLoading = false;
    let endpointEventsLoading = false;

    function endpointIsOnline(host) {
        if (!host.last_heartbeat) return false;

        const heartbeat = new Date(host.last_heartbeat).getTime();
        if (!Number.isFinite(heartbeat)) return false;

        const age = Date.now() - heartbeat;
        return age >= -30000 && age <= 120000;
    }

    function endpointEmptyRow(body, colspan, message) {
        if (!body) return;
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = colspan;
        cell.className = "empty-state";
        cell.textContent = message;
        row.appendChild(cell);
        body.replaceChildren(row);
    }

    async function loadEndpoints() {
        if (endpointHostsLoading || !endpointTableBody) return;

        endpointHostsLoading = true;
        setDisabled($("refreshEndpoints"), true);
        setMessage($("endpointMessage"), "Loading endpoints...");

        try {
            const response = await fetch("/api/endpoints", {
                method: "GET",
                credentials: "same-origin",
                headers: { "Accept": "application/json" }
            });

            const data = await readJSON(response);

            if (!response.ok) {
                throw new Error(data.error || `HTTP ${response.status}`);
            }

            endpointHosts = Array.isArray(data.hosts) ? data.hosts : [];
            renderEndpointHosts();
            setMessage(
                $("endpointMessage"),
                `${endpointHosts.length} endpoint(s) loaded.`
            );
        } catch (error) {
            console.error("Load endpoints error:", error);
            setMessage(
                $("endpointMessage"),
                "Unable to load endpoints. Check your session and try again.",
                "status-error"
            );
            endpointEmptyRow(endpointTableBody, 6, "Endpoint inventory unavailable.");
        } finally {
            endpointHostsLoading = false;
            setDisabled($("refreshEndpoints"), false);
        }
    }

    function renderEndpointHosts() {
        if (!endpointTableBody) return;

        let online = 0;
        endpointTableBody.replaceChildren();

        if (endpointHosts.length === 0) {
            endpointEmptyRow(endpointTableBody, 6, "No endpoints registered yet.");
        }

        for (const host of endpointHosts) {
            const isOnline = endpointIsOnline(host);
            if (isOnline) online++;

            const row = document.createElement("tr");
            row.appendChild(createCell(host.hostname));
            row.appendChild(createCell(String(host.os_type || "").toUpperCase()));
            row.appendChild(createCell(host.agent_version));

            const statusCell = createCell(isOnline ? "Online" : "Offline");
            statusCell.className = isOnline ? "status-success" : "status-warning";
            row.appendChild(statusCell);
            row.appendChild(createCell(formatTimestamp(host.last_heartbeat)));

            const actionCell = document.createElement("td");
            const selectButton = document.createElement("button");
            selectButton.type = "button";
            selectButton.className = "secondary";
            selectButton.textContent =
                selectedEndpointID === host.id ? "Selected" : "View Events";
            selectButton.setAttribute(
                "aria-pressed",
                String(selectedEndpointID === host.id)
            );
            selectButton.addEventListener("click", () => {
                selectedEndpointID = host.id;
                endpointEventOffset = 0;
                renderEndpointHosts();
                loadEndpointEvents();
            });

            actionCell.appendChild(selectButton);
            row.appendChild(actionCell);
            endpointTableBody.appendChild(row);
        }

        if ($("endpointTotal")) $("endpointTotal").textContent = endpointHosts.length;
        if ($("endpointOnline")) $("endpointOnline").textContent = online;
        if ($("endpointOffline")) {
            $("endpointOffline").textContent = endpointHosts.length - online;
        }
    }

    async function loadEndpointEvents() {
        if (endpointEventsLoading || !selectedEndpointID || !endpointEventsBody) {
            return;
        }

        endpointEventsLoading = true;
        setDisabled($("refreshEndpointEvents"), true);
        setDisabled($("applyEndpointFilters"), true);
        setMessage($("endpointEventsMessage"), "Loading endpoint events...");

        const host = endpointHosts.find((item) => item.id === selectedEndpointID);
        if ($("selectedEndpointLabel")) {
            $("selectedEndpointLabel").textContent = host
                ? `${host.hostname} · ${host.os_type}`
                : "Selected endpoint";
        }

        try {
            const params = new URLSearchParams({
                limit: String(ENDPOINT_EVENT_PAGE_SIZE),
                offset: String(endpointEventOffset)
            });

            const response = await fetch(
                `/api/endpoints/${encodeURIComponent(selectedEndpointID)}/events?${params}`,
                {
                    method: "GET",
                    credentials: "same-origin",
                    headers: { "Accept": "application/json" }
                }
            );

            const data = await readJSON(response);
            if (!response.ok) {
                throw new Error(data.error || `HTTP ${response.status}`);
            }

            const events = Array.isArray(data.events) ? data.events : [];
            endpointEventTotal = Number(data.total ?? data.count ?? events.length);
            renderEndpointEvents(events);

            setMessage(
                $("endpointEventsMessage"),
                `${events.length} event(s) on this page.`
            );

            const pageInfo = $("endpointEventsPaginationInfo");
            if (pageInfo) {
                pageInfo.textContent = endpointEventTotal === 0
                    ? "No events"
                    : `Showing ${endpointEventOffset + 1}–${endpointEventOffset + events.length}`;
            }

            setDisabled(
                $("previousEndpointEventsPage"),
                endpointEventOffset === 0
            );
            setDisabled(
                $("nextEndpointEventsPage"),
                events.length < ENDPOINT_EVENT_PAGE_SIZE
            );
        } catch (error) {
            console.error("Load endpoint events error:", error);
            setMessage(
                $("endpointEventsMessage"),
                "Unable to load events for this endpoint.",
                "status-error"
            );
            endpointEmptyRow(endpointEventsBody, 7, "Endpoint events unavailable.");
        } finally {
            endpointEventsLoading = false;
            setDisabled($("refreshEndpointEvents"), !selectedEndpointID);
            setDisabled($("applyEndpointFilters"), !selectedEndpointID);
            setDisabled($("clearEndpointFilters"), !selectedEndpointID);
        }
    }

    function renderEndpointEvents(events) {
        if (!endpointEventsBody) return;

        const severity = String($("endpointSeverityFilter")?.value || "")
            .toLowerCase();

        const filtered = events.filter((event) =>
            !severity || String(event.severity || "").toLowerCase() === severity
        );

        endpointEventsBody.replaceChildren();

        if (filtered.length === 0) {
            endpointEmptyRow(
                endpointEventsBody,
                7,
                severity ? "No events match this severity on the current page."
                        : "No events recorded for this endpoint."
            );
            return;
        }

        for (const event of filtered) {
            const row = document.createElement("tr");
            row.appendChild(createCell(formatTimestamp(event.occurred_at)));
            row.appendChild(createCell(event.event_id));
            row.appendChild(createCell(event.event_type));

            const severityCell = createCell(event.severity);
            severityCell.className = `severity-${String(event.severity || "").toLowerCase()}`;
            row.appendChild(severityCell);

            row.appendChild(createCell(event.risk_score));
            row.appendChild(createCell(event.account));
            row.appendChild(createCell(event.source_ip));
            endpointEventsBody.appendChild(row);
        }
    }

    $("refreshEndpoints")?.addEventListener("click", loadEndpoints);
    $("refreshEndpointEvents")?.addEventListener("click", loadEndpointEvents);

    $("applyEndpointFilters")?.addEventListener("click", () => {
        endpointEventOffset = 0;
        loadEndpointEvents();
    });

    $("clearEndpointFilters")?.addEventListener("click", () => {
        if ($("endpointSeverityFilter")) {
            $("endpointSeverityFilter").value = "";
        }
        endpointEventOffset = 0;
        loadEndpointEvents();
    });

    $("previousEndpointEventsPage")?.addEventListener("click", () => {
        if (endpointEventOffset >= ENDPOINT_EVENT_PAGE_SIZE) {
            endpointEventOffset -= ENDPOINT_EVENT_PAGE_SIZE;
            loadEndpointEvents();
        }
    });

    $("nextEndpointEventsPage")?.addEventListener("click", () => {
        if (endpointEventOffset + ENDPOINT_EVENT_PAGE_SIZE < endpointEventTotal) {
            endpointEventOffset += ENDPOINT_EVENT_PAGE_SIZE;
            loadEndpointEvents();
        }
    });

    /* ---------------- Initial dashboard load ---------------- */

    loadWebsites();
    loadLogs();
    loadAlerts();
    loadEndpoints();
});
