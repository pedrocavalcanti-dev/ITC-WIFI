/* Melhoria progressiva: formulários e CSRF continuam sob controle do Django. */
(() => {
    "use strict";
    const shell = document.querySelector(".portal-shell");
    if (!shell) return;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const tabs = [...document.querySelectorAll("[data-mode]")];
    const panels = [...document.querySelectorAll("[data-panel]")];
    const nav = document.querySelector(".mode-switch");
    const splash = document.querySelector(".splash");
    const submitForms = [...document.querySelectorAll("form[data-submit-label]")];
    let submitting = false;
    shell.inert = Boolean(splash);

    function selectMode(mode, focusHeading = false) {
        if (submitting) return;
        tabs.forEach((tab) => {
            const selected = tab.dataset.mode === mode;
            tab.setAttribute("aria-selected", String(selected));
            tab.tabIndex = selected ? 0 : -1;
        });
        panels.forEach((panel) => {
            const selected = panel.dataset.panel === mode;
            panel.hidden = !selected;
            panel.classList.remove("is-entering");
            if (selected) {
                // Reinicia a transição sem apagar os campos preenchidos.
                void panel.offsetWidth;
                panel.classList.add("is-entering");
                if (focusHeading) panel.querySelector("h1").focus({ preventScroll: true });
            }
        });
        document.title = `${mode === "register" ? "Criar usuário" : "Entrar"} · ITC Wi-Fi`;
    }

    if (nav && panels.length) {
        shell.classList.add("is-enhanced");
        nav.setAttribute("role", "tablist");
        tabs.forEach((tab, index) => {
            tab.id = `mode-${tab.dataset.mode}`;
            tab.setAttribute("role", "tab");
            tab.setAttribute("aria-controls", panels[index].id);
            panels[index].setAttribute("role", "tabpanel");
            panels[index].setAttribute("aria-labelledby", tab.id);
            tab.addEventListener("click", (event) => {
                event.preventDefault();
                selectMode(tab.dataset.mode);
            });
            tab.addEventListener("keydown", (event) => {
                if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
                event.preventDefault();
                let target = tabs[(index + 1) % tabs.length];
                if (event.key === "Home") target = tabs[0];
                if (event.key === "End") target = tabs[tabs.length - 1];
                selectMode(target.dataset.mode);
                target.focus();
            });
        });
        document.querySelectorAll("[data-switch]").forEach((link) => {
            link.addEventListener("click", (event) => {
                event.preventDefault();
                selectMode(link.dataset.switch, true);
            });
        });
        const hashMode = location.hash === "#cadastro" ? "register" : "login";
        const initialMode = shell.dataset.hasSubmission === "true" ? shell.dataset.initialMode : hashMode;
        selectMode(initialMode);
    }

    document.querySelectorAll(".password-toggle").forEach((button) => {
        const input = document.getElementById(button.getAttribute("aria-controls"));
        if (!input) return;
        button.hidden = false;
        button.addEventListener("click", () => {
            const show = input.type === "password";
            input.type = show ? "text" : "password";
            button.setAttribute("aria-label", show ? "Ocultar senha" : "Mostrar senha");
            button.setAttribute("aria-pressed", String(show));
        });
    });

    submitForms.forEach((form) => {
        const button = form.querySelector('[type="submit"]');
        const label = button.querySelector("[data-button-label]");
        button.dataset.originalLabel = label.textContent;
        label.setAttribute("aria-live", "polite");
        form.addEventListener("submit", (event) => {
            if (submitting) {
                event.preventDefault();
                return;
            }
            submitting = true;
            form.setAttribute("aria-busy", "true");
            submitForms.forEach((other) => { other.querySelector('[type="submit"]').disabled = true; });
            button.setAttribute("aria-busy", "true");
            label.textContent = form.dataset.submitLabel;
            const arrow = button.querySelector(".button-arrow");
            if (arrow) arrow.setAttribute("hidden", "");
            button.querySelector(".button-loader").hidden = false;
            // O POST segue normalmente. Não desabilitar inputs ou o token CSRF.
        });
    });

    // Restaurar os controles se o navegador voltar usando o cache de navegação.
    window.addEventListener("pageshow", () => {
        submitting = false;
        submitForms.forEach((form) => {
            const button = form.querySelector('[type="submit"]');
            form.removeAttribute("aria-busy");
            button.removeAttribute("aria-busy");
            button.disabled = false;
            button.querySelector("[data-button-label]").textContent = button.dataset.originalLabel;
            button.querySelector(".button-loader").hidden = true;
            const arrow = button.querySelector(".button-arrow");
            if (arrow) arrow.removeAttribute("hidden");
        });
    });

    function revealPortal() {
        if (splash) splash.remove();
        shell.inert = false;
        const active = panels.find((panel) => !panel.hidden);
        if (active && active.querySelector(".field-errors, .notice.error")) {
            (active.querySelector('[aria-invalid="true"]') || active.querySelector("h1")).focus();
        }
    }
    // Mesmo tempo do CSS; sem JavaScript a animação também libera a página.
    if (splash) window.setTimeout(revealPortal, reduceMotion ? 400 : 2800);
    else revealPortal();
})();
