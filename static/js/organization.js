
"use strict";

(() => {
    const API = {
        members: "/api/organization/members",
        invitations: "/api/organization/invitations"
    };

    const $ = (id) => document.getElementById(id);

    const state = {
        members: [],
        invitations: [],
        invitationsForbidden: false
    };

    // CSRF token
    function csrfToken() {
        const meta = document.querySelector(
            'meta[name="csrf-token"]'
        )?.content?.trim();

        if (meta) return meta;

        const match = document.cookie.match(
            /(?:^|;\s*)secrust_csrf=([^;]+)/
        );

        return match ? decodeURIComponent(match[1]) : "";
    }

    // Common API request handler
    async function apiRequest(url, options = {}) {
        const method = (options.method || "GET").toUpperCase();
        const headers = new Headers(options.headers || {});

        headers.set("Accept", "application/json");

        if (options.body !== undefined) {
            headers.set("Content-Type", "application/json");
        }

        if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
            const token = csrfToken();

            if (!token) {
                throw new Error(
                    "CSRF token missing. Refresh the page and try again."
                );
            }

            headers.set("X-CSRF-Token", token);
        }

        const response = await fetch(url, {
            ...options,
            method,
            headers,
            credentials: "same-origin"
        });

        if (response.status === 204) {
            if (!response.ok) {
                throw new Error(`Request failed (${response.status}).`);
            }

            return null;
        }

        const contentType =
            response.headers.get("content-type") || "";

        let data = {};

        if (contentType.includes("application/json")) {
            data = await response.json();
        } else {
            const text = await response.text();

            if (!response.ok) {
                const error = new Error(
                    text || `Request failed (${response.status}).`
                );

                error.status = response.status;
                throw error;
            }

            return text ? { message: text } : {};
        }

        if (!response.ok) {
            const error = new Error(
                data.error ||
                data.message ||
                `Request failed (${response.status}).`
            );

            error.status = response.status;
            throw error;
        }

        return data;
    }

    // Messages
    function showMessage(id, message, type = "success") {
        const element = $(id);
        if (!element) return;

        element.textContent = message;
        element.className = `message message-${type}`;
        element.hidden = false;
    }

    function clearMessage(id) {
        const element = $(id);
        if (!element) return;

        element.textContent = "";
        element.hidden = true;
    }

    // Table helpers
    function makeCell(value) {
        const td = document.createElement("td");

        td.textContent =
            value == null || value === ""
                ? "—"
                : String(value);

        return td;
    }

    function emptyRow(columns, text) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");

        td.colSpan = columns;
        td.className = "empty";
        td.textContent = text;

        tr.appendChild(td);

        return tr;
    }

    function formatDate(value) {
        if (!value) return "—";

        const date = new Date(value);

        return Number.isNaN(date.getTime())
            ? String(value)
            : date.toLocaleString();
    }

    function roleLabel(role) {
        const labels = {
            SUPER_ADMIN: "Super Admin",
            MANAGER: "Manager",
            ANALYST: "Analyst",
            VIEWER: "Viewer"
        };

        return labels[String(role || "").toUpperCase()]
            || role
            || "—";
    }

    // Invitation status
    function invitationStatus(invitation) {
        if (invitation.accepted_at) {
            return {
                label: "Accepted",
                className: "status-accepted"
            };
        }

        if (invitation.revoked_at) {
            return {
                label: "Revoked",
                className: "status-revoked"
            };
        }

        const expires = invitation.expires_at
            ? new Date(invitation.expires_at).getTime()
            : NaN;

        if (Number.isFinite(expires) && expires <= Date.now()) {
            return {
                label: "Expired",
                className: "status-expired"
            };
        }

        return {
            label: "Pending",
            className: "status-pending"
        };
    }

    function statusBadge(status) {
        const badge = document.createElement("span");

        badge.className = `status ${status.className}`;
        badge.textContent = status.label;

        return badge;
    }

    function setBusy(button, busy, busyText = "Working…") {
        if (!button) return;

        if (busy) {
            if (!button.dataset.originalText) {
                button.dataset.originalText = button.textContent;
            }

            button.textContent = busyText;
            button.disabled = true;
        } else {
            button.textContent =
                button.dataset.originalText || button.textContent;

            delete button.dataset.originalText;
            button.disabled = false;
        }
    }

    // Members
    function renderMembers() {
        const query = ($("memberSearch")?.value || "")
            .trim()
            .toLowerCase();

        const role = ($("roleFilter")?.value || "").toUpperCase();

        const members = state.members.filter((member) => {
            const email = member.email || member.Email || "";
            const memberRole = member.role || member.Role || "";

            const id =
                member.user_id ||
                member.UserID ||
                member.id ||
                member.ID ||
                "";

            const matchesText =
                `${email} ${memberRole} ${id}`
                    .toLowerCase()
                    .includes(query);

            return matchesText &&
                (!role || String(memberRole).toUpperCase() === role);
        });

        const table = $("membersTable");
        table.replaceChildren();

        if (!members.length) {
            table.appendChild(
                emptyRow(
                    3,
                    state.members.length
                        ? "No members match these filters."
                        : "No members found."
                )
            );
        } else {
            for (const member of members) {
                const email =
                    member.email ||
                    member.Email ||
                    member.user_id ||
                    member.UserID ||
                    member.id ||
                    member.ID;

                const memberRole = member.role || member.Role;

                const id =
                    member.user_id ||
                    member.UserID ||
                    member.id ||
                    member.ID;

                const tr = document.createElement("tr");

                tr.append(
                    makeCell(email),
                    makeCell(roleLabel(memberRole)),
                    makeCell(id)
                );

                table.appendChild(tr);
            }
        }

        $("memberCount").textContent =
            `${members.length} of ${state.members.length} member` +
            `${state.members.length === 1 ? "" : "s"}`;

        $("memberStat").textContent = String(state.members.length);
    }

    async function loadMembers() {
        const table = $("membersTable");

        table.replaceChildren(
            emptyRow(3, "Loading members…")
        );

        $("membersMessage").textContent = "";

        try {
            const data = await apiRequest(API.members);

            state.members = Array.isArray(data.members)
                ? data.members
                : [];

            renderMembers();
        } catch (error) {
            table.replaceChildren(
                emptyRow(3, "Unable to load organization members.")
            );

            $("membersMessage").textContent = error.message;
        }
    }

    // Invitations
    function renderInvitations() {
        const query = ($("invitationSearch")?.value || "")
            .trim()
            .toLowerCase();

        const filter = $("invitationStatusFilter")?.value || "";

        const filtered = state.invitations.filter((invitation) => {
            const status = invitationStatus(invitation);

            return String(invitation.email || "")
                .toLowerCase()
                .includes(query) &&
                (!filter || status.label === filter);
        });

        const table = $("invitationsTable");
        table.replaceChildren();

        if (!filtered.length) {
            table.appendChild(
                emptyRow(
                    5,
                    state.invitations.length
                        ? "No invitations match these filters."
                        : "No invitations found."
                )
            );
        } else {
            for (const invitation of filtered) {
                const tr = document.createElement("tr");
                const status = invitationStatus(invitation);

                const statusCell = document.createElement("td");
                statusCell.appendChild(statusBadge(status));

                const actions = document.createElement("td");
                actions.className = "actions";

                tr.append(
                    makeCell(invitation.email),
                    makeCell(roleLabel(invitation.role))
                );

                tr.appendChild(statusCell);
                tr.appendChild(makeCell(formatDate(invitation.expires_at)));

                if (
                    status.label === "Pending" &&
                    !state.invitationsForbidden
                ) {
                    const resend = document.createElement("button");

                    resend.type = "button";
                    resend.className =
                        "button button-secondary button-small";
                    resend.textContent = "Resend";

                    resend.addEventListener("click", () => {
                        resendInvitation(invitation.id, resend);
                    });

                    const revoke = document.createElement("button");

                    revoke.type = "button";
                    revoke.className =
                        "button button-danger button-small";
                    revoke.textContent = "Revoke";

                    revoke.addEventListener("click", () => {
                        revokeInvitation(invitation.id, revoke);
                    });

                    actions.append(resend, revoke);
                } else {
                    actions.textContent = "—";
                }

                tr.appendChild(actions);
                table.appendChild(tr);
            }
        }

        $("invitationCount").textContent =
            `${filtered.length} of ${state.invitations.length} invitation` +
            `${state.invitations.length === 1 ? "" : "s"}`;

        const pending = state.invitations.filter(
            (item) => invitationStatus(item).label === "Pending"
        ).length;

        const accepted = state.invitations.filter(
            (item) => invitationStatus(item).label === "Accepted"
        ).length;

        $("pendingStat").textContent = String(pending);
        $("acceptedStat").textContent = String(accepted);
    }

    async function loadInvitations() {
        const table = $("invitationsTable");

        table.replaceChildren(
            emptyRow(5, "Loading invitations…")
        );

        $("invitationsMessage").textContent = "";

        try {
            const data = await apiRequest(API.invitations);

            state.invitations = Array.isArray(data.invitations)
                ? data.invitations
                : [];

            state.invitationsForbidden = false;

            $("invitePanel").hidden = false;
            $("invitationsPanel").hidden = false;

            renderInvitations();
        } catch (error) {
            if (
                error.status === 403 ||
                /forbidden|insufficient permissions/i.test(error.message)
            ) {
                state.invitationsForbidden = true;
                state.invitations = [];

                $("invitePanel").hidden = true;
                $("invitationsPanel").hidden = true;

                $("invitationsMessage").textContent =
                    "Invitation management is available to Super Admin only.";

                $("pendingStat").textContent = "—";
                $("acceptedStat").textContent = "—";

                return;
            }

            table.replaceChildren(
                emptyRow(5, "Unable to load invitations.")
            );

            $("invitationsMessage").textContent = error.message;
        }
    }

    // Send invitation
    async function sendInvitation(event) {
        event.preventDefault();

        clearMessage("inviteMessage");

        const email = $("inviteEmail").value.trim();
        const role = $("inviteRole").value;
        const button = $("sendInviteButton");

        if (!email) {
            showMessage(
                "inviteMessage",
                "Enter a valid email address.",
                "error"
            );
            return;
        }

        setBusy(button, true, "Sending…");

        try {
            await apiRequest(API.invitations, {
                method: "POST",
                body: JSON.stringify({ email, role })
            });

            $("inviteForm").reset();

            showMessage(
                "inviteMessage",
                "Invitation sent successfully."
            );

            await loadInvitations();
        } catch (error) {
            showMessage(
                "inviteMessage",
                error.message,
                "error"
            );
        } finally {
            setBusy(button, false);
        }
    }

    // Resend invitation
    async function resendInvitation(id, button) {
        if (!id) {
            showMessage(
                "pageMessage",
                "Invitation ID is missing.",
                "error"
            );
            return;
        }

        setBusy(button, true, "Resending…");

        try {
            await apiRequest(
                `${API.invitations}/${encodeURIComponent(id)}/resend`,
                { method: "POST" }
            );

            showMessage(
                "pageMessage",
                "Invitation email resent successfully."
            );

            await loadInvitations();
        } catch (error) {
            showMessage(
                "pageMessage",
                error.message,
                "error"
            );

            setBusy(button, false);
        }
    }

    // Revoke invitation
    async function revokeInvitation(id, button) {
        if (!id) {
            showMessage(
                "pageMessage",
                "Invitation ID is missing.",
                "error"
            );
            return;
        }

        if (
            !window.confirm(
                "Revoke this invitation? This action cannot usually be undone."
            )
        ) {
            return;
        }

        setBusy(button, true, "Revoking…");

        try {
            await apiRequest(
                `${API.invitations}/${encodeURIComponent(id)}`,
                { method: "DELETE" }
            );

            showMessage(
                "pageMessage",
                "Invitation revoked successfully."
            );

            await loadInvitations();
        } catch (error) {
            showMessage(
                "pageMessage",
                error.message,
                "error"
            );

            setBusy(button, false);
        }
    }

    // Refresh page data
    async function refreshPage() {
        clearMessage("pageMessage");

        const button = $("refreshButton");

        setBusy(button, true, "Refreshing…");

        try {
            await Promise.all([
                loadMembers(),
                loadInvitations()
            ]);
        } finally {
            setBusy(button, false);
        }
    }

    // Initialize
    document.addEventListener("DOMContentLoaded", () => {
        $("inviteForm")?.addEventListener(
            "submit",
            sendInvitation
        );

        $("refreshButton")?.addEventListener(
            "click",
            refreshPage
        );

        $("memberSearch")?.addEventListener(
            "input",
            renderMembers
        );

        $("roleFilter")?.addEventListener(
            "change",
            renderMembers
        );

        $("invitationSearch")?.addEventListener(
            "input",
            renderInvitations
        );

        $("invitationStatusFilter")?.addEventListener(
            "change",
            renderInvitations
        );

        refreshPage();
    });
})();
