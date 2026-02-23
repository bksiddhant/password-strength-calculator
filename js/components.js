// ============================================================================
// components.js — DOM Rendering Layer
// All UI built with document.createElement() — NO innerHTML (XSS protection)
// Each function creates and returns DOM elements.
// ============================================================================

// ---------------------------------------------------------------------------
// Utility: element builder
// ---------------------------------------------------------------------------

/**
 * Create a DOM element with attributes, classes, and children
 * @param {string} tag
 * @param {object} opts — { className, id, text, attrs, children, events }
 * @returns {HTMLElement}
 */
function el(tag, opts = {}) {
    const element = document.createElement(tag);

    if (opts.className) element.className = opts.className;
    if (opts.id) element.id = opts.id;
    if (opts.text) element.textContent = opts.text;

    if (opts.attrs) {
        for (const [key, val] of Object.entries(opts.attrs)) {
            element.setAttribute(key, val);
        }
    }

    if (opts.children) {
        for (const child of opts.children) {
            if (child) element.appendChild(child);
        }
    }

    if (opts.events) {
        for (const [event, handler] of Object.entries(opts.events)) {
            element.addEventListener(event, handler);
        }
    }

    return element;
}

// ---------------------------------------------------------------------------
// Score colors
// ---------------------------------------------------------------------------
const SCORE_COLORS = [
    'var(--glow-danger)',     // 0 — Very Weak
    'var(--glow-warning)',    // 1 — Weak
    'var(--color-accent)',    // 2 — Fair
    'var(--glow-success)',    // 3 — Strong
    'var(--glow-success)'    // 4 — Very Strong
];

const SCORE_BG_COLORS = [
    'rgba(255, 82, 82, 0.1)',
    'rgba(255, 183, 77, 0.1)',
    'rgba(196, 232, 255, 0.1)',
    'rgba(0, 230, 118, 0.1)',
    'rgba(0, 230, 118, 0.15)'
];

// ---------------------------------------------------------------------------
// Render: Full App
// ---------------------------------------------------------------------------
export function renderApp(state, container) {
    container.textContent = '';

    const wrapper = el('div', {
        className: 'app-wrapper',
        children: [
            renderHeader(state),
            renderTabs(state.activeTab),
            renderMainContent(state),
            renderFooter()
        ]
    });

    container.appendChild(wrapper);
}

// ---------------------------------------------------------------------------
// Render: Header
// ---------------------------------------------------------------------------
function renderHeader(state) {
    const titleRow = el('div', {
        className: 'header-title-row',
        children: [
            el('div', {
                className: 'header-left',
                children: [
                    el('div', {
                        className: 'header-icon',
                        text: '🔐'
                    }),
                    el('div', {
                        children: [
                            el('h1', {
                                className: 'header-title',
                                text: 'Password Strength Calculator'
                            }),
                            el('p', {
                                className: 'header-subtitle',
                                text: 'Privacy-first analysis • Zero data collection • Fully offline'
                            })
                        ]
                    })
                ]
            }),
            renderDarkModeToggle(state.darkMode)
        ]
    });

    return el('header', {
        className: 'app-header',
        children: [titleRow]
    });
}

// ---------------------------------------------------------------------------
// Render: Dark Mode Toggle
// ---------------------------------------------------------------------------
function renderDarkModeToggle(darkMode) {
    const toggle = el('button', {
        className: 'dark-mode-toggle',
        id: 'dark-mode-toggle',
        text: darkMode ? '☀️' : '🌙',
        attrs: {
            'aria-label': darkMode ? 'Switch to light mode' : 'Switch to dark mode',
            'data-action': 'toggle-dark-mode'
        }
    });

    return toggle;
}

// ---------------------------------------------------------------------------
// Render: Tabs
// ---------------------------------------------------------------------------
function renderTabs(activeTab) {
    const tabs = ['analyzer', 'generator'];
    const labels = { analyzer: '🔍 Analyzer', generator: '⚡ Generator' };

    const tabButtons = tabs.map(tab => {
        return el('button', {
            className: `tab-btn ${activeTab === tab ? 'tab-btn--active' : ''}`,
            id: `tab-${tab}`,
            text: labels[tab],
            attrs: {
                'data-action': 'switch-tab',
                'data-tab': tab,
                'role': 'tab',
                'aria-selected': activeTab === tab ? 'true' : 'false'
            }
        });
    });

    return el('nav', {
        className: 'tabs',
        attrs: { 'role': 'tablist' },
        children: tabButtons
    });
}

// ---------------------------------------------------------------------------
// Render: Main Content (tab switcher)
// ---------------------------------------------------------------------------
function renderMainContent(state) {
    const content = state.activeTab === 'analyzer'
        ? renderAnalyzer(state.analyzer)
        : renderGenerator(state.generator);

    return el('main', {
        className: 'main-content',
        children: [content]
    });
}

// ---------------------------------------------------------------------------
// Render: Analyzer
// ---------------------------------------------------------------------------
function renderAnalyzer(analyzerState) {
    const { password, showPassword, showDetails, personalInputs, result } = analyzerState;

    const children = [
        renderPasswordInput(password, showPassword),
        renderPersonalInputs(personalInputs),
    ];

    if (password.length > 0) {
        children.push(
            renderStrengthMeter(result.score, result.strengthLabel),
            renderMetricsRow(result),
            renderCrackTimes(result.crackTimes),
            renderPatterns(result.patterns),
            renderFeedback(result.warnings, result.suggestions),
            renderDetailsToggle(showDetails, result)
        );
    } else {
        children.push(renderEmptyState());
    }

    return el('section', {
        className: 'analyzer-section',
        id: 'analyzer-panel',
        attrs: { 'role': 'tabpanel' },
        children
    });
}

// ---------------------------------------------------------------------------
// Render: Password Input
// ---------------------------------------------------------------------------
function renderPasswordInput(password, showPassword) {
    const input = el('input', {
        className: 'password-input',
        id: 'password-input',
        attrs: {
            type: showPassword ? 'text' : 'password',
            placeholder: 'Enter your password to analyze...',
            value: password,
            autocomplete: 'off',
            autocapitalize: 'off',
            spellcheck: 'false',
            'data-action': 'password-input'
        }
    });

    const toggleBtn = el('button', {
        className: 'visibility-toggle',
        id: 'visibility-toggle',
        text: showPassword ? '🙈' : '👁️',
        attrs: {
            'aria-label': showPassword ? 'Hide password' : 'Show password',
            'data-action': 'toggle-visibility'
        }
    });

    return el('div', {
        className: 'input-group',
        children: [input, toggleBtn]
    });
}

// ---------------------------------------------------------------------------
// Render: Personal Inputs
// ---------------------------------------------------------------------------
function renderPersonalInputs(personalInputs) {
    const nameInput = el('input', {
        className: 'personal-input',
        id: 'personal-name',
        attrs: {
            type: 'text',
            placeholder: 'Your name (optional)',
            value: personalInputs.name,
            autocomplete: 'off',
            'data-action': 'personal-name'
        }
    });

    const emailInput = el('input', {
        className: 'personal-input',
        id: 'personal-email',
        attrs: {
            type: 'text',
            placeholder: 'Your email (optional)',
            value: personalInputs.email,
            autocomplete: 'off',
            'data-action': 'personal-email'
        }
    });

    return el('div', {
        className: 'personal-inputs',
        children: [
            el('p', {
                className: 'personal-label',
                text: 'Optional: Check for personal info in password'
            }),
            el('div', {
                className: 'personal-row',
                children: [nameInput, emailInput]
            })
        ]
    });
}

// ---------------------------------------------------------------------------
// Render: Strength Meter
// ---------------------------------------------------------------------------
function renderStrengthMeter(score, label) {
    const percentage = ((score + 1) / 5) * 100;
    const color = SCORE_COLORS[score] || SCORE_COLORS[0];

    const fill = el('div', {
        className: 'meter-fill',
        attrs: {
            style: `width: ${percentage}%; background: ${color};`
        }
    });

    const meter = el('div', {
        className: 'meter-track',
        children: [fill]
    });

    const labelEl = el('span', {
        className: `meter-label meter-label--score-${score}`,
        text: label,
        attrs: {
            style: `color: ${color};`
        }
    });

    return el('div', {
        className: 'strength-meter',
        children: [
            el('div', {
                className: 'meter-header',
                children: [
                    el('span', { className: 'meter-title', text: 'Strength' }),
                    labelEl
                ]
            }),
            meter
        ]
    });
}

// ---------------------------------------------------------------------------
// Render: Metrics Row
// ---------------------------------------------------------------------------
function renderMetricsRow(result) {
    const metrics = [
        {
            label: 'Entropy',
            value: `${result.entropy} bits`,
            tooltip: 'Entropy measures the unpredictability of your password in bits. Higher is better.'
        },
        {
            label: 'Guesses',
            value: result.guessesDisplay?.log || '0',
            sub: result.guessesDisplay?.human || '',
            tooltip: 'Estimated number of guesses an attacker needs to crack this password.'
        }
    ];

    const cards = metrics.map(m => {
        const children = [
            el('span', { className: 'metric-label', text: m.label }),
            el('span', { className: 'metric-value', text: m.value })
        ];
        if (m.sub) {
            children.push(el('span', { className: 'metric-sub', text: m.sub }));
        }

        return el('div', {
            className: 'metric-card',
            attrs: { 'title': m.tooltip },
            children
        });
    });

    return el('div', {
        className: 'metrics-row',
        children: cards
    });
}

// ---------------------------------------------------------------------------
// Render: Crack Times
// ---------------------------------------------------------------------------
function renderCrackTimes(crackTimes) {
    const scenarios = [
        { key: 'onlineThrottled', label: 'Online Attack', sub: '~100 guesses/hr', icon: '🌐' },
        { key: 'offlineSlowHash', label: 'Offline (bcrypt)', sub: '~10⁵ guesses/sec', icon: '🔒' },
        { key: 'offlineFastHash', label: 'Offline (MD5)', sub: '~10¹¹ guesses/sec', icon: '⚡' }
    ];

    const rows = scenarios.map(s => {
        return el('div', {
            className: 'crack-row',
            children: [
                el('div', {
                    className: 'crack-scenario',
                    children: [
                        el('span', { className: 'crack-icon', text: s.icon }),
                        el('div', {
                            children: [
                                el('span', { className: 'crack-label', text: s.label }),
                                el('span', { className: 'crack-sub', text: s.sub })
                            ]
                        })
                    ]
                }),
                el('span', {
                    className: 'crack-time',
                    text: crackTimes[s.key] || '—'
                })
            ]
        });
    });

    return el('div', {
        className: 'crack-times',
        children: [
            el('h3', { className: 'section-heading', text: '⏱️ Time to Crack' }),
            ...rows
        ]
    });
}

// ---------------------------------------------------------------------------
// Render: Patterns
// ---------------------------------------------------------------------------
function renderPatterns(patterns) {
    if (!patterns || patterns.length === 0) return null;

    const severityClass = {
        high: 'chip--danger',
        moderate: 'chip--warning',
        info: 'chip--info'
    };

    const chips = patterns.map(p => {
        return el('span', {
            className: `pattern-chip ${severityClass[p.severity] || 'chip--info'}`,
            text: p.message,
            attrs: { 'title': `Pattern: ${p.type}, Token: ${p.token}` }
        });
    });

    return el('div', {
        className: 'patterns-section',
        children: [
            el('h3', { className: 'section-heading', text: '🔍 Detected Patterns' }),
            el('div', { className: 'pattern-chips', children: chips })
        ]
    });
}

// ---------------------------------------------------------------------------
// Render: Feedback (warnings + suggestions)
// ---------------------------------------------------------------------------
function renderFeedback(warnings, suggestions) {
    if ((!warnings || warnings.length === 0) && (!suggestions || suggestions.length === 0)) {
        return null;
    }

    const children = [];

    if (warnings && warnings.length > 0) {
        const warningItems = warnings.map(w =>
            el('li', {
                className: `feedback-item feedback-item--${w.severity}`,
                text: w.text
            })
        );
        children.push(
            el('div', {
                className: 'feedback-block feedback-block--warnings',
                children: [
                    el('h4', { className: 'feedback-heading', text: '⚠️ Warnings' }),
                    el('ul', { className: 'feedback-list', children: warningItems })
                ]
            })
        );
    }

    if (suggestions && suggestions.length > 0) {
        const suggestionItems = suggestions.map(s =>
            el('li', { className: 'feedback-item feedback-item--suggestion', text: s })
        );
        children.push(
            el('div', {
                className: 'feedback-block feedback-block--suggestions',
                children: [
                    el('h4', { className: 'feedback-heading', text: '💡 Suggestions' }),
                    el('ul', { className: 'feedback-list', children: suggestionItems })
                ]
            })
        );
    }

    return el('div', {
        className: 'feedback-section',
        children
    });
}

// ---------------------------------------------------------------------------
// Render: Details Toggle (Why is this weak?)
// ---------------------------------------------------------------------------
function renderDetailsToggle(showDetails, result) {
    const toggle = el('button', {
        className: 'details-toggle',
        id: 'details-toggle',
        text: showDetails ? '▾ Hide Details' : '▸ Why is this score?',
        attrs: { 'data-action': 'toggle-details' }
    });

    const children = [toggle];

    if (showDetails) {
        const detailContent = el('div', {
            className: 'details-panel',
            children: [
                el('div', {
                    className: 'detail-row',
                    children: [
                        el('span', { className: 'detail-label', text: 'Password Length:' }),
                        el('span', { className: 'detail-value', text: `${result.entropy > 0 ? 'Analyzed' : 'N/A'}` })
                    ]
                }),
                el('div', {
                    className: 'detail-row',
                    children: [
                        el('span', { className: 'detail-label', text: 'Patterns Found:' }),
                        el('span', { className: 'detail-value', text: `${result.patterns.length}` })
                    ]
                }),
                el('div', {
                    className: 'detail-row',
                    children: [
                        el('span', { className: 'detail-label', text: 'Is Passphrase:' }),
                        el('span', { className: 'detail-value', text: result.isPassphrase ? 'Yes ✓' : 'No' })
                    ]
                }),
                el('p', {
                    className: 'detail-explanation',
                    text: result.score <= 1
                        ? 'Your password scored low because attackers use pattern-based cracking that checks common passwords, keyboard patterns, sequences, and dictionary words before brute-forcing. Length and randomness are the strongest defences.'
                        : result.score <= 2
                            ? 'Your password has moderate strength. While it avoids the most common patterns, increasing length or using a passphrase would significantly improve security.'
                            : 'Your password is strong. It would require significant computational resources to crack via brute-force methods.'
                })
            ]
        });
        children.push(detailContent);
    }

    return el('div', {
        className: 'details-section',
        children
    });
}

// ---------------------------------------------------------------------------
// Render: Empty State
// ---------------------------------------------------------------------------
function renderEmptyState() {
    return el('div', {
        className: 'empty-state',
        children: [
            el('div', { className: 'empty-icon', text: '🔒' }),
            el('h3', {
                className: 'empty-title',
                text: 'Enter a password to begin analysis'
            }),
            el('p', {
                className: 'empty-description',
                text: 'Your password never leaves your device. All analysis happens locally in your browser.'
            })
        ]
    });
}

// ---------------------------------------------------------------------------
// Render: Generator
// ---------------------------------------------------------------------------
export function renderGenerator(generatorState) {
    const {
        password, length, includeUpper, includeLower,
        includeNumbers, includeSymbols, passphraseMode,
        wordCount, copied, strength
    } = generatorState;

    return el('section', {
        className: 'generator-section',
        id: 'generator-panel',
        attrs: { 'role': 'tabpanel' },
        children: [
            renderGeneratorOutput(password, copied),
            renderGeneratorControls(
                length, includeUpper, includeLower,
                includeNumbers, includeSymbols, passphraseMode, wordCount
            ),
            renderGeneratorActions(),
            password ? renderGeneratorStrength(strength) : null
        ]
    });
}

// --- Generator Output ---
function renderGeneratorOutput(password, copied) {
    const outputText = el('span', {
        className: 'generator-password',
        id: 'generator-output',
        text: password || 'Click "Generate" to create a password'
    });

    const copyBtn = el('button', {
        className: `copy-btn ${copied ? 'copy-btn--copied' : ''}`,
        id: 'copy-btn',
        text: copied ? '✓ Copied' : '📋 Copy',
        attrs: {
            'data-action': 'copy-password',
            disabled: !password ? 'true' : undefined
        }
    });

    if (!password) copyBtn.setAttribute('disabled', 'true');

    return el('div', {
        className: 'generator-output-group',
        children: [outputText, copyBtn]
    });
}

// --- Generator Controls ---
function renderGeneratorControls(length, upper, lower, numbers, symbols, passphrase, wordCount) {
    const children = [];

    // Mode toggle
    children.push(
        el('div', {
            className: 'control-row',
            children: [
                el('label', {
                    className: 'control-label',
                    text: 'Passphrase Mode',
                    attrs: { for: 'passphrase-toggle' }
                }),
                renderToggleSwitch('passphrase-toggle', passphrase, 'toggle-passphrase')
            ]
        })
    );

    if (passphrase) {
        // Word count slider
        children.push(
            el('div', {
                className: 'control-row',
                children: [
                    el('label', {
                        className: 'control-label',
                        text: `Word Count: ${wordCount}`,
                        attrs: { for: 'word-count-slider' }
                    }),
                    el('input', {
                        className: 'range-slider',
                        id: 'word-count-slider',
                        attrs: {
                            type: 'range',
                            min: '3',
                            max: '8',
                            value: String(wordCount),
                            'data-action': 'word-count'
                        }
                    })
                ]
            })
        );
    } else {
        // Length slider
        children.push(
            el('div', {
                className: 'control-row',
                children: [
                    el('label', {
                        className: 'control-label',
                        text: `Length: ${length}`,
                        attrs: { for: 'length-slider' }
                    }),
                    el('input', {
                        className: 'range-slider',
                        id: 'length-slider',
                        attrs: {
                            type: 'range',
                            min: '8',
                            max: '64',
                            value: String(length),
                            'data-action': 'set-length'
                        }
                    })
                ]
            })
        );

        // Character set toggles
        const charsets = [
            { id: 'toggle-lower', label: 'Lowercase (a-z)', checked: lower, action: 'toggle-lower' },
            { id: 'toggle-upper', label: 'Uppercase (A-Z)', checked: upper, action: 'toggle-upper' },
            { id: 'toggle-numbers', label: 'Numbers (0-9)', checked: numbers, action: 'toggle-numbers' },
            { id: 'toggle-symbols', label: 'Symbols (!@#$)', checked: symbols, action: 'toggle-symbols' }
        ];

        const toggles = charsets.map(cs => {
            return el('div', {
                className: 'control-row control-row--compact',
                children: [
                    el('label', {
                        className: 'control-label',
                        text: cs.label,
                        attrs: { for: cs.id }
                    }),
                    renderToggleSwitch(cs.id, cs.checked, cs.action)
                ]
            });
        });

        children.push(
            el('div', { className: 'charset-toggles', children: toggles })
        );
    }

    return el('div', { className: 'generator-controls', children });
}

// --- Toggle Switch ---
function renderToggleSwitch(id, checked, action) {
    const track = el('div', {
        className: `toggle-track ${checked ? 'toggle-track--active' : ''}`,
        id: id,
        attrs: {
            'role': 'switch',
            'aria-checked': String(checked),
            'data-action': action,
            'tabindex': '0'
        },
        children: [
            el('div', { className: 'toggle-thumb' })
        ]
    });

    return track;
}

// --- Generator Actions ---
function renderGeneratorActions() {
    return el('div', {
        className: 'generator-actions',
        children: [
            el('button', {
                className: 'btn btn--primary',
                id: 'generate-btn',
                text: '⚡ Generate',
                attrs: { 'data-action': 'generate' }
            }),
            el('button', {
                className: 'btn btn--secondary',
                id: 'regenerate-btn',
                text: '🔄 Regenerate',
                attrs: { 'data-action': 'regenerate' }
            })
        ]
    });
}

// --- Generator Strength Display ---
function renderGeneratorStrength(strength) {
    if (!strength || strength.score === undefined) return null;

    const color = SCORE_COLORS[strength.score] || SCORE_COLORS[0];
    const percentage = ((strength.score + 1) / 5) * 100;

    return el('div', {
        className: 'generator-strength',
        children: [
            el('div', {
                className: 'meter-header',
                children: [
                    el('span', { className: 'meter-title', text: 'Generated Password Strength' }),
                    el('span', {
                        className: 'meter-label',
                        text: strength.label,
                        attrs: { style: `color: ${color};` }
                    })
                ]
            }),
            el('div', {
                className: 'meter-track',
                children: [
                    el('div', {
                        className: 'meter-fill',
                        attrs: { style: `width: ${percentage}%; background: ${color};` }
                    })
                ]
            }),
            strength.entropy ? el('span', {
                className: 'generator-entropy',
                text: `${strength.entropy} bits of entropy`
            }) : null
        ]
    });
}

// ---------------------------------------------------------------------------
// Render: Footer
// ---------------------------------------------------------------------------
function renderFooter() {
    return el('footer', {
        className: 'app-footer',
        children: [
            el('p', {
                className: 'footer-text',
                text: '🔒 Your password never leaves your device. All analysis is performed locally in your browser with zero data collection.'
            }),
            el('p', {
                className: 'footer-credit',
                text: 'Built with vanilla HTML, CSS & JavaScript — Zero dependencies'
            })
        ]
    });
}
