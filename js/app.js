// ============================================================================
// app.js — Main Entry Point
// Sets up event delegation, wires state changes, and manages the render loop.
// ============================================================================

import { getState, getStateRef, setState, subscribe, batchUpdate } from './state.js';
import { analyzePassword } from './analyzer.js';
import { generatePassword, generatePassphrase } from './generator.js';
import { renderApp } from './components.js';

// ---------------------------------------------------------------------------
// DOM Ready
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    const appContainer = document.getElementById('app');

    if (!appContainer) {
        console.error('[B.L.A.S.T.] #app container not found.');
        return;
    }

    console.log('[B.L.A.S.T.] Password Strength Calculator initialized.');

    // Check dark mode preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        setState('darkMode', true);
        document.documentElement.setAttribute('data-theme', 'dark');
    }

    // Initial render
    renderApp(getStateRef(), appContainer);

    // Subscribe: re-render on any state change
    subscribe((state) => {
        renderApp(state, appContainer);
        // Restore focus/cursor position after render
        restoreFocus();
    });

    // ---------------------------------------------------------------------------
    // Event Delegation — all events handled on #app
    // ---------------------------------------------------------------------------
    let debounceTimer = null;
    let focusedElementId = null;
    let cursorPosition = 0;

    appContainer.addEventListener('input', (e) => {
        const action = e.target.dataset.action;
        if (!action) return;

        // Save focus state before re-render
        saveFocus(e.target);

        switch (action) {
            case 'password-input':
                // Debounce password analysis at 250ms
                clearTimeout(debounceTimer);
                setState('analyzer.password', e.target.value);
                debounceTimer = setTimeout(() => {
                    const state = getStateRef();
                    const result = analyzePassword(
                        state.analyzer.password,
                        state.analyzer.personalInputs
                    );
                    setState('analyzer.result', result);
                }, 250);
                // Immediate render for password field update (responsive feel)
                break;

            case 'personal-name':
                setState('analyzer.personalInputs.name', e.target.value);
                triggerReanalysis();
                break;

            case 'personal-email':
                setState('analyzer.personalInputs.email', e.target.value);
                triggerReanalysis();
                break;

            case 'set-length':
                // Update label visually during drag without triggering re-render
                const lengthLabel = document.querySelector('label[for="length-slider"]');
                if (lengthLabel) lengthLabel.textContent = `Length: ${e.target.value}`;
                break;

            case 'word-count':
                // Update label visually during drag without triggering re-render
                const wordLabel = document.querySelector('label[for="word-count-slider"]');
                if (wordLabel) wordLabel.textContent = `Word Count: ${e.target.value}`;
                break;
        }
    });

    appContainer.addEventListener('change', (e) => {
        const action = e.target.dataset.action;
        if (!action) return;

        switch (action) {
            case 'set-length':
                setState('generator.length', parseInt(e.target.value, 10));
                break;

            case 'word-count':
                setState('generator.wordCount', parseInt(e.target.value, 10));
                break;
        }
    });

    appContainer.addEventListener('click', (e) => {
        const target = e.target.closest('[data-action]');
        if (!target) return;

        const action = target.dataset.action;

        switch (action) {
            case 'switch-tab':
                setState('activeTab', target.dataset.tab);
                break;

            case 'toggle-visibility':
                setState('analyzer.showPassword', !getStateRef().analyzer.showPassword);
                break;

            case 'toggle-details':
                setState('analyzer.showDetails', !getStateRef().analyzer.showDetails);
                break;

            case 'toggle-dark-mode':
                toggleDarkMode();
                break;

            case 'generate':
            case 'regenerate':
                handleGenerate();
                break;

            case 'copy-password':
                handleCopy();
                break;

            case 'toggle-passphrase':
                setState('generator.passphraseMode', !getStateRef().generator.passphraseMode);
                break;

            case 'toggle-lower':
                setState('generator.includeLower', !getStateRef().generator.includeLower);
                break;

            case 'toggle-upper':
                setState('generator.includeUpper', !getStateRef().generator.includeUpper);
                break;

            case 'toggle-numbers':
                setState('generator.includeNumbers', !getStateRef().generator.includeNumbers);
                break;

            case 'toggle-symbols':
                setState('generator.includeSymbols', !getStateRef().generator.includeSymbols);
                break;
        }
    });

    // Keyboard support for toggle switches
    appContainer.addEventListener('keydown', (e) => {
        const target = e.target.closest('[data-action]');
        if (!target) return;

        if (e.key === 'Enter' || e.key === ' ') {
            const action = target.dataset.action;
            if (action && action.startsWith('toggle-')) {
                e.preventDefault();
                target.click();
            }
        }
    });

    // ---------------------------------------------------------------------------
    // Handlers
    // ---------------------------------------------------------------------------
    function triggerReanalysis() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            const state = getStateRef();
            if (state.analyzer.password) {
                const result = analyzePassword(
                    state.analyzer.password,
                    state.analyzer.personalInputs
                );
                setState('analyzer.result', result);
            }
        }, 250);
    }

    function handleGenerate() {
        const state = getStateRef();
        let password;

        if (state.generator.passphraseMode) {
            password = generatePassphrase(state.generator.wordCount);
        } else {
            password = generatePassword({
                length: state.generator.length,
                includeUpper: state.generator.includeUpper,
                includeLower: state.generator.includeLower,
                includeNumbers: state.generator.includeNumbers,
                includeSymbols: state.generator.includeSymbols
            });
        }

        // Analyze the generated password
        const result = analyzePassword(password);

        batchUpdate((set) => {
            set('generator.password', password);
            set('generator.copied', false);
            set('generator.strength', {
                score: result.score,
                label: result.strengthLabel,
                entropy: result.entropy
            });
        });
    }

    function handleCopy() {
        const state = getStateRef();
        if (!state.generator.password) return;

        navigator.clipboard.writeText(state.generator.password).then(() => {
            setState('generator.copied', true);
            setTimeout(() => {
                setState('generator.copied', false);
            }, 2000);
        }).catch(() => {
            // Fallback: manual copy
            const textarea = document.createElement('textarea');
            textarea.value = state.generator.password;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            setState('generator.copied', true);
            setTimeout(() => {
                setState('generator.copied', false);
            }, 2000);
        });
    }

    function toggleDarkMode() {
        const newMode = !getStateRef().darkMode;
        setState('darkMode', newMode);
        document.documentElement.setAttribute('data-theme', newMode ? 'dark' : 'light');
    }

    // ---------------------------------------------------------------------------
    // Focus management — preserve cursor position across re-renders
    // ---------------------------------------------------------------------------
    function saveFocus(element) {
        focusedElementId = element.id;
        if (element.selectionStart !== undefined) {
            cursorPosition = element.selectionStart;
        }
    }

    function restoreFocus() {
        if (!focusedElementId) return;
        requestAnimationFrame(() => {
            const el = document.getElementById(focusedElementId);
            if (el) {
                el.focus();
                if (el.setSelectionRange && cursorPosition !== undefined) {
                    try {
                        el.setSelectionRange(cursorPosition, cursorPosition);
                    } catch (_) {
                        // Some input types don't support setSelectionRange
                    }
                }
            }
        });
    }
});
