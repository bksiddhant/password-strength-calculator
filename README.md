# Password Strength Calculator & Generator

A privacy-first, zero-dependency password strength analyzer and secure generator. Built with a focus on deep heuristics, transparency, and military-grade offline security.

## 🚀 Overview

This application evaluates password strength using advanced crack-resistance heuristics. Unlike basic calculators that only count characters, this tool analyzes patterns, dictionary matches, common sequences, and provides realistic crack-time estimates for various attack scenarios.

### 🛡️ Privacy & Security
- **100% Offline**: All calculations happen in your browser. No data ever leaves your device.
- **Zero Networking**: No tracking, no cookies, and no telemetry.
- **No Persistence**: Passwords are never saved to local storage or databases.

---

## ✨ Key Features

- **Advanced Analyzer**:
  - **Dictionary Attacks**: Checks against the top 10,000 most common passwords.
  - **Pattern Recognition**: Detects repeated characters, sequences (abc, 123), and keyboard patterns.
  - **L33t Speak Support**: Recognizes common character substitutions (e.g., P@ssw0rd).
  - **Entropy Calculation**: Theoretical bit-strength and guessable complexity.
  - **Crack-Time Estimation**: Estimates time for online throttling, offline slow hashing (Bcrypt), and fast hashing (MD5/SHA).
- **Secure Generator**:
  - Customizable character sets (Uppercase, Lowercase, Numbers, Symbols).
  - High-entropy passphrase generation.
  - Real-time strength feedback for generated passwords.
- **Clean UI/UX**:
  - Dark Mode support.
  - State-first architecture for snappy, lag-free interactions.

---

### Tech Stack
- **Structure**: Semantic HTML5
- **Styling**: Vanilla CSS (CSS Variables, Flexbox/Grid)
- **Logic**: ES6+ JavaScript Modules
- **Frameworks**: ❌ None (Zero dependencies)

### File Structure
```text
├── index.html          # Main entry point
├── css/
│   └── style.css       # Custom design system & variables
└── js/
    ├── app.js         # Application bootstrapper
    ├── state.js       # Centralized state management
    ├── components.js  # Render functions & UI logic
    ├── analyzer.js    # Core heuristic engine
    ├── generator.js   # Secure password logic
    └── data.js        # Wordlists & common password datasets
```

---

## 🛠️ Local Development

Since this is a client-side application using **ES6 Modules**, it requires a local server to run (browsers block modules via `file://` protocol).

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/password-strength-calculator.git
   ```

2. **Run a local server**:
   You can use any light server. For example:
   ```bash
   # Using Python
   python -m http.server 8000

   # Using Node.js (Live Server)
   npx live-server
   ```

3. **Open in Browser**:
   Navigate to `http://localhost:8000`.

---

*Built with ❤️ for privacy and security.*
