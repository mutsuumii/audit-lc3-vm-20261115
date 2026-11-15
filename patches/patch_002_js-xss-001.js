# DOM XSS via innerHTML
# CWE-79 | Severity: HIGH
# File: docs/google-code-prettify/prettify.js line 26

**Risk:** Setting innerHTML with user data allows script injection in other users' browsers.

**Fix:** Use textContent. If HTML is needed, sanitize with DOMPurify.sanitize() first.
