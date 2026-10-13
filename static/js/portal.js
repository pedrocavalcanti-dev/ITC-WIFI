/* ITC Wi-Fi — Script moderno de interação e aprimoramento progressivo do portal.
   Formulários, validações e tokens CSRF permanecem totalmente controlados pelo Django. */
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

    // Acessibilidade: bloqueia foco durante breve splash de abertura
    if (splash) {
        shell.inert = true;
    }

    /**
     * Alterna a aba ativa entre "login" e "register"
     * @param {string} mode - "login" ou "register"
     * @param {boolean} focusHeading - foca no título para leitores de tela
     */
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
                // Reinicia a transição CSS sem perder os valores digitados nos inputs
                void panel.offsetWidth;
                panel.classList.add("is-entering");
                if (focusHeading) {
                    const heading = panel.querySelector("h1");
                    if (heading) heading.focus({ preventScroll: true });
                }
            }
        });

        document.title = `${mode === "register" ? "Criar usuário" : "Entrar"} · ITC Wi-Fi`;
    }

    // Inicialização da navegação por abas acessível (WAI-ARIA Tabs)
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
                if (event.key === "ArrowLeft") target = tabs[(index - 1 + tabs.length) % tabs.length];

                selectMode(target.dataset.mode);
                target.focus();
            });
        });

        // Links de atalho em texto auxiliar ("Criar usuário" / "Já tenho usuário")
        document.querySelectorAll("[data-switch]").forEach((link) => {
            link.addEventListener("click", (event) => {
                event.preventDefault();
                selectMode(link.dataset.switch, true);
            });
        });

        // Detecção inicial: se houve erro de validação em cadastro, abre cadastro; senão respeita hash ou login
        const hashMode = location.hash === "#cadastro" ? "register" : "login";
        const initialMode = shell.dataset.hasSubmission === "true" ? shell.dataset.initialMode : hashMode;
        selectMode(initialMode);
    }

    // Controle de exibição/ocultação de senha
    document.querySelectorAll(".password-toggle").forEach((button) => {
        const inputId = button.getAttribute("aria-controls");
        const input = document.getElementById(inputId);
        if (!input) return;

        button.hidden = false;
        button.addEventListener("click", () => {
            const isPassword = input.type === "password";
            input.type = isPassword ? "text" : "password";
            button.setAttribute("aria-label", isPassword ? "Ocultar senha" : "Mostrar senha");
            button.setAttribute("aria-pressed", String(isPassword));
            input.focus();
        });
    });

    // Tratamento de loading em formulários de autenticação
    submitForms.forEach((form) => {
        const button = form.querySelector('[type="submit"]');
        if (!button) return;

        const label = button.querySelector("[data-button-label]");
        if (label) {
            button.dataset.originalLabel = label.textContent;
            label.setAttribute("aria-live", "polite");
        }

        form.addEventListener("submit", (event) => {
            if (submitting) {
                event.preventDefault();
                return;
            }
            submitting = true;
            form.setAttribute("aria-busy", "true");

            submitForms.forEach((other) => {
                const otherBtn = other.querySelector('[type="submit"]');
                if (otherBtn) otherBtn.disabled = true;
            });

            button.setAttribute("aria-busy", "true");
            if (label && form.dataset.submitLabel) {
                label.textContent = form.dataset.submitLabel;
            }

            const arrow = button.querySelector(".button-arrow");
            if (arrow) arrow.setAttribute("hidden", "");

            const loader = button.querySelector(".button-loader");
            if (loader) loader.hidden = false;

            // O envio POST padrão do navegador ocorre intacto com todos os campos e CSRF
        });
    });

    // Restaura o estado da interface caso o navegador volte através do histórico ou bfcache
    window.addEventListener("pageshow", () => {
        submitting = false;
        submitForms.forEach((form) => {
            const button = form.querySelector('[type="submit"]');
            if (!button) return;

            form.removeAttribute("aria-busy");
            button.removeAttribute("aria-busy");
            button.disabled = false;

            const label = button.querySelector("[data-button-label]");
            if (label && button.dataset.originalLabel) {
                label.textContent = button.dataset.originalLabel;
            }

            const loader = button.querySelector(".button-loader");
            if (loader) loader.hidden = true;

            const arrow = button.querySelector(".button-arrow");
            if (arrow) arrow.removeAttribute("hidden");
        });
    });

    /**
     * Remove suavemente a vinheta de splash inicial e posiciona o foco
     */
    function revealPortal() {
        if (splash) {
            splash.classList.add("is-finished");
            window.setTimeout(() => {
                splash.remove();
            }, 300);
        }

        shell.inert = false;

        // Caso haja erros de validação retornados pelo Django, foca no primeiro campo com erro
        const activePanel = panels.find((panel) => !panel.hidden);
        if (activePanel) {
            const invalidField = activePanel.querySelector('[aria-invalid="true"]');
            if (invalidField) {
                invalidField.focus({ preventScroll: true });
            }
        }
    }

    // Abertura ágil e suave: no máximo 450ms (ou imediato se prefers-reduced-motion)
    if (splash) {
        window.setTimeout(revealPortal, reduceMotion ? 50 : 450);
    } else {
        revealPortal();
    }
})();
