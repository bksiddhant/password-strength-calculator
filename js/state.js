// ============================================================================
// state.js — Centralized State Management
// Single source of truth. All mutations via setState(). Triggers re-render.
// No persistence — fully ephemeral, resets on page refresh.
// ============================================================================

const appState = {
    activeTab: 'analyzer',
    darkMode: false,

    analyzer: {
        password: '',
        showPassword: false,
        showDetails: false,
        personalInputs: { name: '', email: '' },
        result: {
            score: 0,
            entropy: 0,
            guesses: 0,
            crackTimes: {
                onlineThrottled: '',
                offlineSlowHash: '',
                offlineFastHash: ''
            },
            strengthLabel: 'N/A',
            patterns: [],
            warnings: [],
            suggestions: [],
            isPassphrase: false
        }
    },

    generator: {
        password: '',
        length: 16,
        includeUpper: true,
        includeLower: true,
        includeNumbers: true,
        includeSymbols: true,
        passphraseMode: false,
        wordCount: 4,
        copied: false,
        strength: {
            score: 0,
            label: 'N/A',
            entropy: 0
        }
    }
};

// Listeners that get called on state change
const listeners = [];

/**
 * Get a deep clone of the current state
 * @returns {object} State snapshot
 */
export function getState() {
    return JSON.parse(JSON.stringify(appState));
}

/**
 * Get direct reference (for reads only, avoid mutation)
 * @returns {object} Direct state reference
 */
export function getStateRef() {
    return appState;
}

/**
 * Update state at a given dot-notation path and notify listeners
 * @param {string} path — e.g. 'analyzer.password' or 'generator.length'
 * @param {*} value — new value
 */
export function setState(path, value) {
    const keys = path.split('.');
    let current = appState;

    for (let i = 0; i < keys.length - 1; i++) {
        if (current[keys[i]] === undefined) {
            current[keys[i]] = {};
        }
        current = current[keys[i]];
    }

    current[keys[keys.length - 1]] = value;

    // Notify all subscribers
    for (const listener of listeners) {
        listener(appState);
    }
}

/**
 * Subscribe a listener function to state changes
 * @param {function} fn — called with full state on every change
 * @returns {function} Unsubscribe function
 */
export function subscribe(fn) {
    listeners.push(fn);
    return () => {
        const idx = listeners.indexOf(fn);
        if (idx > -1) listeners.splice(idx, 1);
    };
}

/**
 * Batch multiple state updates, notifying listeners only once at the end
 * @param {function} updateFn — receives setState-like setter
 */
export function batchUpdate(updateFn) {
    const batchListeners = [...listeners];
    listeners.length = 0;

    updateFn(setState);

    listeners.push(...batchListeners);

    // Single notification
    for (const listener of listeners) {
        listener(appState);
    }
}
