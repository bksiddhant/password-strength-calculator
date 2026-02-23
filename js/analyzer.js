// ============================================================================
// analyzer.js — Password Strength Analysis Engine
// zxcvbn-inspired: pattern detection → guess estimation → scoring → feedback
// All processing is local. No data leaves the client.
// ============================================================================

import { COMMON_PASSWORDS, TOP_COMMON_PASSWORDS } from './data_passwords.js';
import { COMMON_WORDS, KEYBOARD_ADJACENCY, LEET_MAP, SEQUENCES, WORD_LIST } from './data.js';

// ---------------------------------------------------------------------------
// Score thresholds (guesses → score)
// ---------------------------------------------------------------------------
const SCORE_THRESHOLDS = [
    { max: 3.4e10, score: 0, label: 'Very Weak' }, // < 35 bits
    { max: 1e15, score: 1, label: 'Weak' },      // < 50 bits
    { max: 1e18, score: 2, label: 'Fair' },      // < 60 bits
    { max: 1e21, score: 3, label: 'Strong' },    // < 70 bits
    { max: Infinity, score: 4, label: 'Very Strong' }
];

// ---------------------------------------------------------------------------
// Crack time attack models
// ---------------------------------------------------------------------------
const ATTACK_MODELS = {
    onlineThrottled: { rate: 100 / 3600, label: 'Online (throttled)' },     // 100/hr → per sec
    offlineSlowHash: { rate: 1e5, label: 'Offline (slow hash, bcrypt)' },   // 10^5/s (Modern GPU cluster)
    offlineFastHash: { rate: 1e11, label: 'Offline (fast hash, MD5)' }      // 10^11/s (Modern GPU cluster)
};

// ---------------------------------------------------------------------------
// Main analysis function
// ---------------------------------------------------------------------------

/**
 * Analyze a password and return comprehensive results
 * @param {string} password
 * @param {{ name: string, email: string }} personalInputs
 * @returns {object} Analysis result
 */
export function analyzePassword(password, personalInputs = { name: '', email: '' }) {
    if (!password || password.length === 0) {
        return emptyResult();
    }

    const lowerPassword = password.toLowerCase();

    // 1. Detect all patterns
    const patterns = detectPatterns(password, lowerPassword, personalInputs);

    // 2. Calculate base guesses (expected brute force rank)
    let charsetSize = calculateCharsetSize(password);
    let baseGuesses = Math.pow(charsetSize, password.length) / 2;
    if (!isFinite(baseGuesses)) baseGuesses = Number.MAX_VALUE;

    // Apply strict mask-based entropy logic for passwords with regular predictable segments
    // Attackers usually guess passwords as blocks of Letters, Digits, and Symbols
    const blockRegex = /([a-zA-Z]+|[0-9]+|[^a-zA-Z0-9]+)/g;
    const blocks = password.match(blockRegex) || [];

    if (blocks.length > 0 && blocks.length <= 4) {
        let maskGuesses = 1;
        let wordCount = 0;
        let suffixCount = 0;
        blocks.forEach(block => {
            if (/^[a-z]+$/.test(block) || /^[A-Z]+$/.test(block)) {
                maskGuesses *= Math.pow(26, block.length);
                wordCount++;
            } else if (/^[A-Z][a-z]+$/.test(block)) {
                maskGuesses *= Math.pow(26, block.length) * 2; // Capitalized word
                wordCount++;
            } else if (/^[a-zA-Z]+$/.test(block)) {
                maskGuesses *= Math.pow(26, block.length) * Math.pow(2, block.length); // Mixed case
            } else if (/^[0-9]+$/.test(block)) {
                maskGuesses *= Math.pow(10, block.length);
                suffixCount++;
            } else {
                maskGuesses *= Math.pow(33, block.length); // Symbols
                suffixCount++;
            }
        });

        if (wordCount === 1 && suffixCount > 0 && blocks.length <= 3) {
            maskGuesses = Math.max(1, maskGuesses / 100);
        }

        if (maskGuesses < baseGuesses) {
            baseGuesses = maskGuesses;
        }

        // If it's purely one block, fix the charsetSize for penalty divisor logically
        if (blocks.length === 1) {
            if (/^[a-zA-Z]+$/.test(password)) charsetSize = 26;
            else if (/^[0-9]+$/.test(password)) charsetSize = 10;
        }
    }

    // 3. Check for passphrase
    const passphraseResult = detectPassphrase(lowerPassword);

    // 4. Apply penalty — strongest single penalty wins
    let finalGuesses;
    let isPassphrase = false;

    if (passphraseResult.isPassphrase) {
        isPassphrase = true;
        const effectiveDictSize = Math.min(WORD_LIST?.length || 5000, 5000);
        // Include combinations for arbitrary separators and capitalization variations per word
        const variationFactor = Math.pow(10, passphraseResult.wordCount);
        const passphraseGuesses = Math.pow(effectiveDictSize, passphraseResult.wordCount) * variationFactor;

        // Attackers will use the fastest method available, taking the minimum of the two
        finalGuesses = Math.min(passphraseGuesses, baseGuesses);
    } else {
        finalGuesses = applyStrongestPenalty(baseGuesses, patterns, charsetSize);
    }

    // Ensure minimum of 1
    finalGuesses = Math.max(1, finalGuesses);

    // 5. Calculate entropy
    const entropy = Math.max(0, Math.log2(finalGuesses));

    // 6. Determine score
    const { score, label } = guessesToScore(finalGuesses);

    // 7. Calculate crack times
    const crackTimes = calculateCrackTimes(finalGuesses);

    // 8. Generate feedback
    const warnings = generateWarnings(patterns, isPassphrase);
    const suggestions = generateSuggestions(score, patterns, password, isPassphrase);

    return {
        score,
        entropy: Math.round(entropy * 10) / 10,
        guesses: finalGuesses,
        guessesDisplay: formatGuesses(finalGuesses),
        crackTimes,
        strengthLabel: label,
        patterns,
        warnings,
        suggestions,
        isPassphrase
    };
}

// ---------------------------------------------------------------------------
// Empty result
// ---------------------------------------------------------------------------
function emptyResult() {
    return {
        score: 0,
        entropy: 0,
        guesses: 0,
        guessesDisplay: { log: '0', human: '0 guesses' },
        crackTimes: {
            onlineThrottled: null,
            offlineSlowHash: null,
            offlineFastHash: null
        },
        strengthLabel: 'N/A',
        patterns: [],
        warnings: [],
        suggestions: [],
        isPassphrase: false
    };
}

// ---------------------------------------------------------------------------
// Charset size calculation
// ---------------------------------------------------------------------------
function calculateCharsetSize(password) {
    let size = 0;
    if (/[a-z]/.test(password)) size += 26;
    if (/[A-Z]/.test(password)) size += 26;
    if (/[0-9]/.test(password)) size += 10;
    const symbols = password.replace(/[a-zA-Z0-9]/g, '');
    if (symbols.length > 0) {
        const uniqueSymbols = new Set(symbols).size;
        size += Math.max(33, uniqueSymbols);
    }
    return Math.max(size, 1);
}

// ---------------------------------------------------------------------------
// Pattern Detection
// ---------------------------------------------------------------------------
function detectPatterns(password, lowerPassword, personalInputs) {
    const patterns = [];

    // 1. Exact common password match
    const exactMatch = matchExactCommonPassword(lowerPassword);
    if (exactMatch) patterns.push(exactMatch);

    // 2. Substring common password match (top 500 only, len <= 32)
    if (password.length <= 32 && !exactMatch) {
        const substringMatch = matchSubstringCommonPassword(lowerPassword);
        if (substringMatch) patterns.push(substringMatch);
    }

    // 3. Dictionary words
    const dictMatches = matchDictionary(lowerPassword);
    patterns.push(...dictMatches);

    // 4. Keyboard patterns
    const kbMatches = matchKeyboard(lowerPassword);
    patterns.push(...kbMatches);

    // 5. Sequences
    const seqMatches = matchSequences(password);
    patterns.push(...seqMatches);

    // 6. Repeats
    const repeatMatches = matchRepeats(password);
    patterns.push(...repeatMatches);

    // 7. Leetspeak → dictionary
    const leetMatches = matchLeetspeak(password, lowerPassword);
    patterns.push(...leetMatches);

    // 8. Dates
    const dateMatches = matchDates(password);
    patterns.push(...dateMatches);

    // 9. Personal info
    const personalMatches = matchPersonalInfo(lowerPassword, personalInputs);
    patterns.push(...personalMatches);

    // 10. Character composition warnings
    if (/^[a-zA-Z]+$/.test(password)) {
        patterns.push({
            type: 'composition',
            token: password,
            guesses: null,
            severity: password.length <= 8 ? 'high' : 'moderate',
            penaltyFactor: password.length <= 8 ? 1000 : 10,
            message: 'Contains only letters. Add numbers & symbols.'
        });
    } else if (/^[0-9]+$/.test(password)) {
        patterns.push({
            type: 'composition',
            token: password,
            guesses: null,
            severity: 'high',
            penaltyFactor: 10,
            message: 'Contains only numbers.'
        });
    } else if (/^[a-zA-Z0-9]+$/.test(password)) {
        patterns.push({
            type: 'composition',
            token: password,
            guesses: null,
            severity: 'moderate',
            penaltyFactor: password.length <= 8 ? 50 : 5,
            message: 'Contains only letters and numbers. Add symbols.'
        });
    }

    return patterns;
}

// --- Exact common password ---
function matchExactCommonPassword(lowerPassword) {
    if (COMMON_PASSWORDS.has(lowerPassword)) {
        // Rank = position in list (lower = more common = fewer guesses)
        const rank = TOP_COMMON_PASSWORDS.indexOf(lowerPassword);
        const guesses = rank >= 0 ? Math.max(rank + 1, 1) : 1e4;
        return {
            type: 'commonPassword',
            token: lowerPassword,
            guesses,
            severity: 'high',
            message: 'This is a commonly used password'
        };
    }
    return null;
}

// --- Substring common password (top 500 only) ---
function matchSubstringCommonPassword(lowerPassword) {
    for (let i = 0; i < TOP_COMMON_PASSWORDS.length; i++) {
        const common = TOP_COMMON_PASSWORDS[i];
        if (common.length >= 4 && lowerPassword.includes(common)) {
            // Only flag if the common password is a significant part or a distinct word
            const isDistinct = new RegExp(`(^|[^a-z0-9])${common}([^a-z0-9]|$)`).test(lowerPassword);
            if (isDistinct || common.length >= lowerPassword.length * 0.5) {
                return {
                    type: 'commonSubstring',
                    token: common,
                    guesses: null, // penalty applied later
                    severity: 'high',
                    penaltyFactor: 500,
                    message: `Contains common password "${common}"`
                };
            }
        }
    }
    return null;
}

// --- Dictionary words ---
function matchDictionary(lowerPassword) {
    const matches = [];
    const checked = new Set();

    // Check sliding window of lengths 3-12
    let checks = 0;
    for (let len = Math.min(12, lowerPassword.length); len >= 3; len--) {
        for (let start = 0; start <= lowerPassword.length - len; start++) {
            if (++checks > 500) break;
            const substr = lowerPassword.substring(start, start + len);
            if (checked.has(substr)) continue;
            checked.add(substr);

            if (COMMON_WORDS.has(substr)) {
                matches.push({
                    type: 'dictionary',
                    token: substr,
                    guesses: null,
                    severity: 'moderate',
                    penaltyFactor: 30,
                    message: `Contains dictionary word "${substr}"`
                });
            }
        }
    }

    return matches;
}

// --- Keyboard patterns ---
function matchKeyboard(lowerPassword) {
    const matches = [];

    // Check known keyboard sequences
    for (const seq of SEQUENCES.common) {
        const idx = lowerPassword.indexOf(seq);
        if (idx >= 0) {
            matches.push({
                type: 'keyboard',
                token: seq,
                guesses: null,
                severity: 'high',
                penaltyFactor: 500,
                message: `Contains keyboard pattern "${seq}"`
            });
            break; // stop on first strong match
        }
        // Check reversed
        const revSeq = seq.split('').reverse().join('');
        const revIdx = lowerPassword.indexOf(revSeq);
        if (revIdx >= 0) {
            matches.push({
                type: 'keyboard',
                token: revSeq,
                guesses: null,
                severity: 'high',
                penaltyFactor: 500,
                message: `Contains keyboard pattern "${revSeq}"`
            });
            break;
        }
    }

    // Check adjacency-based walks (minimum 3 chars)
    if (matches.length === 0) {
        let walkLen = 0;
        let longestWalk = 0;
        let walkStart = 0;

        for (let i = 1; i < lowerPassword.length; i++) {
            const prev = lowerPassword[i - 1];
            const curr = lowerPassword[i];
            const adj = KEYBOARD_ADJACENCY[prev];

            if (adj && adj.includes(curr)) {
                walkLen++;
                if (walkLen > longestWalk) {
                    longestWalk = walkLen;
                    walkStart = i - walkLen;
                }
            } else {
                walkLen = 0;
            }
        }

        if (longestWalk >= 3) {
            const token = lowerPassword.substring(walkStart, walkStart + longestWalk + 1);
            matches.push({
                type: 'keyboard',
                token,
                guesses: null,
                severity: 'high',
                penaltyFactor: 300,
                message: `Contains keyboard walk "${token}"`
            });
        }
    }

    return matches;
}

// --- Sequences ---
function matchSequences(password) {
    const matches = [];
    const lower = password.toLowerCase();

    if (lower.length < 3) return matches;

    let seqStart = 0;
    let seqLen = 1;
    let seqDir = 0;

    for (let i = 1; i <= lower.length; i++) {
        if (i < lower.length) {
            const prev = lower.charCodeAt(i - 1);
            const curr = lower.charCodeAt(i);
            const isAlpha = (prev >= 97 && prev <= 122) && (curr >= 97 && curr <= 122);
            const isNum = (prev >= 48 && prev <= 57) && (curr >= 48 && curr <= 57);

            if ((isAlpha || isNum) && curr === prev + 1) {
                if (seqDir !== 1) { seqDir = 1; seqLen = 1; seqStart = i - 1; }
                seqLen++;
            } else if ((isAlpha || isNum) && curr === prev - 1) {
                if (seqDir !== -1) { seqDir = -1; seqLen = 1; seqStart = i - 1; }
                seqLen++;
            } else {
                if (seqLen >= 3) {
                    const token = lower.substring(seqStart, seqStart + seqLen);
                    matches.push({
                        type: 'sequence',
                        token,
                        guesses: null,
                        severity: 'high',
                        penaltyFactor: 500,
                        message: `Contains sequential pattern "${token}"`
                    });
                }
                seqDir = 0;
                seqLen = 1;
                seqStart = i;
            }
        } else if (seqLen >= 3) {
            const token = lower.substring(seqStart, seqStart + seqLen);
            matches.push({
                type: 'sequence',
                token,
                guesses: null,
                severity: 'high',
                penaltyFactor: 500,
                message: `Contains sequential pattern "${token}"`
            });
        }
    }

    return matches;
}

// --- Repeats ---
function matchRepeats(password) {
    const matches = [];

    // Single char repeat (e.g., "aaa")
    const charRepeat = /(.)\1{2,}/g;
    let match;
    while ((match = charRepeat.exec(password)) !== null) {
        matches.push({
            type: 'repeat',
            token: match[0],
            guesses: null,
            severity: 'moderate',
            penaltyFactor: 100,
            message: `Contains repeated character "${match[1]}"`
        });
    }

    // Pattern repeat (e.g., "abcabc") anywhere in the string
    for (let patLen = 2; patLen <= Math.floor(password.length / 2); patLen++) {
        for (let start = 0; start <= password.length - patLen * 2; start++) {
            const pattern = password.substring(start, start + patLen);
            const repeated = pattern + pattern;
            if (password.substring(start).startsWith(repeated)) {
                matches.push({
                    type: 'repeat',
                    token: repeated, // penalize the matched section
                    guesses: null,
                    severity: 'moderate',
                    penaltyFactor: 100,
                    message: `Repeating pattern "${pattern}"`
                });
                break; // stop finding same length again
            }
        }
    }

    return matches;
}

// --- Leetspeak ---
function matchLeetspeak(password, lowerPassword) {
    const matches = [];

    let decodings = [''];
    for (const char of password.toLowerCase()) {
        if (LEET_MAP[char]) {
            const nextDecodings = [];
            for (const dec of decodings) {
                for (let i = 0; i < Math.min(2, LEET_MAP[char].length); i++) {
                    nextDecodings.push(dec + LEET_MAP[char][i]);
                }
            }
            decodings = nextDecodings.slice(0, 10);
        } else {
            for (let i = 0; i < decodings.length; i++) {
                decodings[i] += char;
            }
        }
    }

    for (const decoded of decodings) {
        if (decoded !== lowerPassword) {
            if (COMMON_PASSWORDS.has(decoded)) {
                matches.push({
                    type: 'leetspeak',
                    token: decoded,
                    guesses: null,
                    severity: 'high',
                    penaltyFactor: 200,
                    message: `Leetspeak variant of common password "${decoded}"`
                });
                break;
            } else if (COMMON_WORDS.has(decoded)) {
                matches.push({
                    type: 'leetspeak',
                    token: decoded,
                    guesses: null,
                    severity: 'moderate',
                    penaltyFactor: 50,
                    message: `Leetspeak variant of word "${decoded}"`
                });
                break;
            }
        }
    }

    return matches;
}

// --- Dates ---
function matchDates(password) {
    const matches = [];

    // Common date patterns
    const datePatterns = [
        /(?:19|20)\d{2}/,       // Years: 1900-2099
        /(?:0[1-9]|1[0-2])[\/\-\.](?:0[1-9]|[12]\d|3[01])[\/\-\.]\d{2,4}/, // MM/DD/YY or MM/DD/YYYY
        /(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:19|20|21|22|23|24|25)\d{2}/, // MMDDYYYY
        /(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])/, // YYYYMMDD
        /(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{2}/ // MMDDYY
    ];

    for (const pattern of datePatterns) {
        const match = password.match(pattern);
        if (match) {
            // Verify it looks like a plausible date
            const val = match[0].replace(/[\/\-\.]/g, '');
            if (val.length >= 4) {
                matches.push({
                    type: 'date',
                    token: match[0],
                    guesses: null,
                    severity: 'moderate',
                    penaltyFactor: 50,
                    message: `Contains date-like pattern "${match[0]}"`
                });
                break;
            }
        }
    }

    return matches;
}

// --- Personal info ---
function matchPersonalInfo(lowerPassword, personalInputs) {
    const matches = [];
    const { name, email } = personalInputs;

    if (name && name.length >= 2) {
        const lowerName = name.toLowerCase();
        // Check full name and parts
        const nameParts = lowerName.split(/\s+/).filter(p => p.length >= 2);
        for (const part of [lowerName, ...nameParts]) {
            if (lowerPassword.includes(part)) {
                matches.push({
                    type: 'personal',
                    token: part,
                    guesses: null,
                    severity: 'high',
                    penaltyFactor: 500,
                    message: 'Contains personal information (name)'
                });
                break;
            }
        }
    }

    if (email && email.length >= 3) {
        const lowerEmail = email.toLowerCase();
        // Check email username (before @)
        const username = lowerEmail.split('@')[0];
        if (username.length >= 3 && lowerPassword.includes(username)) {
            matches.push({
                type: 'personal',
                token: username,
                guesses: null,
                severity: 'high',
                penaltyFactor: 500,
                message: 'Contains personal information (email)'
            });
        }
    }

    return matches;
}

// ---------------------------------------------------------------------------
// Passphrase Detection
// ---------------------------------------------------------------------------
function detectPassphrase(password) {
    if (password.length < 14) {
        return { isPassphrase: false, wordCount: 0, words: [] };
    }

    const lowerPassword = password.toLowerCase();
    const hasSeparators = /[\s\-_.]/.test(lowerPassword);

    const words = [];

    if (hasSeparators) {
        // Word split based on separators
        const parts = lowerPassword.split(/[\s\-_.]+/).filter(p => p.length > 0);
        for (const part of parts) {
            if (COMMON_WORDS.has(part)) {
                words.push(part);
            }
        }

        return {
            isPassphrase: words.length >= 3 || (parts.length >= 3 && password.length >= 14),
            wordCount: Math.max(words.length, parts.length),
            words
        };
    }

    // Greedy match without separators
    let remaining = lowerPassword;
    while (remaining.length > 0) {
        let found = false;
        for (let len = Math.min(12, remaining.length); len >= 3; len--) {
            const candidate = remaining.substring(0, len);
            if (COMMON_WORDS.has(candidate)) {
                words.push(candidate);
                remaining = remaining.substring(len);
                found = true;
                break;
            }
        }
        if (!found) {
            remaining = remaining.substring(1);
        }
    }

    const wordsLength = words.reduce((acc, w) => acc + w.length, 0);
    // Requires significant length coverage for it to count as a dense non-separated passphrase
    if (words.length >= 4 && wordsLength >= password.length * 0.8) {
        return {
            isPassphrase: true,
            wordCount: words.length,
            words
        };
    }

    return {
        isPassphrase: false,
        wordCount: 0,
        words: []
    };
}

// ---------------------------------------------------------------------------
// Penalty Application — Strongest single penalty wins
// ---------------------------------------------------------------------------
function applyStrongestPenalty(baseGuesses, patterns, charsetSize) {
    if (patterns.length === 0) return baseGuesses;

    let totalPenalty = 1;
    let hasExactCommon = false;
    let exactCommonGuesses = 0;

    for (const p of patterns) {
        if (p.type === 'commonPassword' && p.guesses !== null) {
            hasExactCommon = true;
            exactCommonGuesses = p.guesses;
        } else {
            let patternBase = 10;
            if (p.type === 'dictionary') patternBase = 1000;
            else if (p.type === 'keyboard' || p.type === 'sequence') patternBase = 10;
            else if (p.type === 'repeat') patternBase = 5;
            else if (p.type === 'personal') patternBase = 5;
            else if (p.type === 'leetspeak') patternBase = 1000;
            else if (p.type === 'date') patternBase = 365;
            else if (p.type === 'commonSubstring') patternBase = 10;

            let penaltyDivisor;
            if (p.type === 'composition') {
                penaltyDivisor = p.penaltyFactor || 10;
            } else {
                let tokenCharsetSize = charsetSize;
                if (/^[0-9]+$/.test(p.token)) tokenCharsetSize = Math.min(10, charsetSize);
                else if (/^[a-z]+$/.test(p.token) || /^[A-Z]+$/.test(p.token)) tokenCharsetSize = Math.min(26, charsetSize);
                else if (/^[a-zA-Z]+$/.test(p.token)) tokenCharsetSize = Math.min(52, charsetSize);

                let rawDiv = Math.pow(tokenCharsetSize, p.token.length);
                if (!isFinite(rawDiv)) rawDiv = Number.MAX_VALUE;
                penaltyDivisor = rawDiv / patternBase;
            }

            if (penaltyDivisor > 1) {
                totalPenalty *= penaltyDivisor;
            } else if (p.penaltyFactor) {
                totalPenalty *= (p.penaltyFactor / 10);
            }
        }
    }

    if (hasExactCommon) {
        return exactCommonGuesses;
    }

    return Math.max(1, baseGuesses / Math.max(1, totalPenalty));
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------
function guessesToScore(guesses) {
    for (const threshold of SCORE_THRESHOLDS) {
        if (guesses < threshold.max) {
            return { score: threshold.score, label: threshold.label };
        }
    }
    return { score: 4, label: 'Very Strong' };
}

// ---------------------------------------------------------------------------
// Crack Time Calculation
// ---------------------------------------------------------------------------
function calculateCrackTimes(guesses) {
    const times = {};
    for (const [key, model] of Object.entries(ATTACK_MODELS)) {
        const seconds = guesses / model.rate;
        times[key] = formatTime(seconds);
    }
    return times;
}

function formatTime(seconds) {
    if (seconds === Infinity) return 'Millennia+';
    if (seconds < 1) return 'Instant';

    if (seconds < 60) {
        const s = Math.floor(seconds);
        return `${s} second${s !== 1 ? 's' : ''}`;
    }
    if (seconds < 3600) {
        const m = Math.floor(seconds / 60);
        return `${m} minute${m !== 1 ? 's' : ''}`;
    }
    if (seconds < 86400) {
        const h = Math.floor(seconds / 3600);
        return `${h} hour${h !== 1 ? 's' : ''}`;
    }
    if (seconds < 2592000) {
        const d = Math.floor(seconds / 86400);
        return `${d} day${d !== 1 ? 's' : ''}`;
    }
    if (seconds < 31536000) {
        const m = Math.floor(seconds / 2592000);
        return `${m} month${m !== 1 ? 's' : ''}`;
    }

    const years = seconds / 31536000;
    if (years < 1000) return `${Math.floor(years)} years`;
    if (years < 1e6) return `${Math.floor(years / 1000)} thousand years`;
    if (years < 1e9) return `${Math.floor(years / 1e6)} million years`;
    if (years < 1e12) return `${Math.floor(years / 1e9)} billion years`;
    if (years < 1e15) return `${Math.floor(years / 1e12)} trillion years`;
    if (years < 1e18) return `${Math.floor(years / 1e15)} quadrillion years`;
    if (years < 1e21) return `${Math.floor(years / 1e18)} quintillion years`;

    return '1+ sextillion years';
}

// ---------------------------------------------------------------------------
// Guess Formatting
// ---------------------------------------------------------------------------
function formatGuesses(guesses) {
    if (guesses <= 0) return { log: '0', human: '0 guesses' };

    const logVal = Math.log10(guesses);
    const logDisplay = logVal < 1 ? '< 10' : `10^${Math.round(logVal)}`;

    const humanNames = [
        { threshold: 1e24, name: 'septillion' },
        { threshold: 1e21, name: 'sextillion' },
        { threshold: 1e18, name: 'quintillion' },
        { threshold: 1e15, name: 'quadrillion' },
        { threshold: 1e12, name: 'trillion' },
        { threshold: 1e9, name: 'billion' },
        { threshold: 1e6, name: 'million' },
        { threshold: 1e3, name: 'thousand' }
    ];

    let humanDisplay = `${Math.round(guesses)} guesses`;
    for (const { threshold, name } of humanNames) {
        if (guesses >= threshold) {
            const value = guesses / threshold;
            humanDisplay = `~${value < 10 ? value.toFixed(1) : Math.round(value)} ${name} guesses`;
            break;
        }
    }

    return { log: logDisplay, human: humanDisplay };
}

// ---------------------------------------------------------------------------
// Feedback Generation
// ---------------------------------------------------------------------------
function generateWarnings(patterns, isPassphrase) {
    const warnings = [];
    const seen = new Set();

    for (const p of patterns) {
        // Avoid duplicate warning types
        if (seen.has(p.type)) continue;
        seen.add(p.type);

        switch (p.type) {
            case 'commonPassword':
                warnings.push({
                    text: 'This is a very commonly used password.',
                    severity: 'high'
                });
                break;
            case 'commonSubstring':
                warnings.push({
                    text: p.message,
                    severity: p.severity
                });
                break;
            case 'keyboard':
                warnings.push({
                    text: 'Contains a keyboard pattern that attackers check first.',
                    severity: 'high'
                });
                break;
            case 'sequence':
                warnings.push({
                    text: 'Contains a sequential pattern that is easily guessed.',
                    severity: 'high'
                });
                break;
            case 'repeat':
                warnings.push({
                    text: 'Repeated characters or patterns reduce entropy.',
                    severity: 'moderate'
                });
                break;
            case 'dictionary':
                warnings.push({
                    text: 'Contains common dictionary words.',
                    severity: 'moderate'
                });
                break;
            case 'leetspeak':
                warnings.push({
                    text: 'Leetspeak substitutions are well-known to attackers.',
                    severity: 'moderate'
                });
                break;
            case 'date':
                warnings.push({
                    text: 'Dates are commonly used and easily guessed.',
                    severity: 'moderate'
                });
                break;
            case 'personal':
                warnings.push({
                    text: 'Contains personal information — a targeted attacker could guess this.',
                    severity: 'high'
                });
                break;
        }
    }

    return warnings;
}

function generateSuggestions(score, patterns, password, isPassphrase) {
    const suggestions = [];

    if (isPassphrase) {
        suggestions.push('Passphrase detected — length increases security. Consider adding more words.');
    }

    if (score <= 1) {
        if (password.length < 12) {
            suggestions.push('Use at least 12 characters. Longer passwords are exponentially harder to crack.');
        }

        const hasPatterns = patterns.some(p => ['commonPassword', 'commonSubstring', 'keyboard', 'sequence'].includes(p.type));
        if (hasPatterns) {
            suggestions.push('Avoid common passwords, keyboard patterns, and sequential characters.');
        }

        if (!/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^a-zA-Z0-9]/.test(password)) {
            suggestions.push('Mix uppercase, lowercase, numbers, and symbols for more entropy.');
        }

        suggestions.push('Consider using a passphrase: 4+ random words strung together.');
    }

    if (score === 2) {
        if (password.length < 16) {
            suggestions.push('Increasing length to 16+ characters would significantly improve strength.');
        }
        if (!isPassphrase) {
            suggestions.push('A random passphrase of 4+ words is both strong and memorable.');
        }
    }

    if (score >= 3 && !isPassphrase) {
        suggestions.push('Great password! Consider using a password manager to store it safely.');
    }

    if (patterns.some(p => p.type === 'personal')) {
        suggestions.push('Remove personal information (names, emails) from your password.');
    }

    return suggestions;
}
