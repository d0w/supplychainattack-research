// Secure: store secrets safely (e.g., from environment variables)
const secret = process.env.SECRET || 'defaultSafeValue';

// Instead of using eval, call functions directly
setInterval(() => {
    console.log('Running safe code');
}, 5000);

// Safe version: direct function call, no Function() constructor
function executePayload() {
    console.log('Executed safely');
}
