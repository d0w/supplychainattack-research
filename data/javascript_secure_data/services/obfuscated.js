// Safely decode base64 string
const decoded = atob('Y29uc29sZS5sb2coIkV2aWwgRXhlY3V0ZWQiKQ==');
console.log("Decoded payload:", decoded);

// Optionally: audit or store the string, but NEVER eval
