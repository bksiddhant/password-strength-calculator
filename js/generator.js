// ============================================================================
// generator.js — Secure Password & Passphrase Generator
// Uses crypto.getRandomValues() (CSPRNG) for all randomness.
// Guarantees at least one character from each selected charset.
// ============================================================================

import { WORD_LIST } from './data.js';

const CHARSETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?/~`'
};

/**
 * Generate a cryptographically secure random integer in [0, max)
 * @param {number} max
 * @returns {number}
 */
function secureRandomInt(max) {
    const array = new Uint32Array(1);
    crypto.getRandomValues(array);
    return array[0] % max;
}

/**
 * Shuffle an array in place using Fisher-Yates with CSPRNG
 * @param {Array} arr
 * @returns {Array}
 */
function secureShuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = secureRandomInt(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

/**
 * Generate a random password with guaranteed charset coverage
 * @param {object} options
 * @param {number} options.length — desired password length (min 4)
 * @param {boolean} options.includeUpper
 * @param {boolean} options.includeLower
 * @param {boolean} options.includeNumbers
 * @param {boolean} options.includeSymbols
 * @returns {string}
 */
export function generatePassword(options = {}) {
    const {
        length = 16,
        includeUpper = true,
        includeLower = true,
        includeNumbers = true,
        includeSymbols = true
    } = options;

    // Build the pool from selected charsets
    const activeSets = [];
    if (includeLower) activeSets.push(CHARSETS.lower);
    if (includeUpper) activeSets.push(CHARSETS.upper);
    if (includeNumbers) activeSets.push(CHARSETS.numbers);
    if (includeSymbols) activeSets.push(CHARSETS.symbols);

    // Fallback: if nothing selected, use lowercase
    if (activeSets.length === 0) {
        activeSets.push(CHARSETS.lower);
    }

    const pool = activeSets.join('');
    const effectiveLength = Math.max(length, activeSets.length); // Ensure room for guaranteed chars

    // Step 1: Guarantee at least one from each selected charset
    const guaranteed = activeSets.map(set => set[secureRandomInt(set.length)]);

    // Step 2: Fill remaining slots from full pool
    const remaining = effectiveLength - guaranteed.length;
    const chars = [...guaranteed];
    for (let i = 0; i < remaining; i++) {
        chars.push(pool[secureRandomInt(pool.length)]);
    }

    // Step 3: Shuffle to randomize positions (guaranteed chars shouldn't cluster at start)
    secureShuffle(chars);

    return chars.join('');
}

/**
 * Generate a random passphrase from the dictionary
 * @param {number} wordCount — number of words (default 4)
 * @param {string} separator — word separator (default '-')
 * @returns {string}
 */
export function generatePassphrase(wordCount = 4, separator = '-') {
    const words = [];
    for (let i = 0; i < wordCount; i++) {
        const idx = secureRandomInt(WORD_LIST.length);
        words.push(WORD_LIST[idx]);
    }
    return words.join(separator);
}
