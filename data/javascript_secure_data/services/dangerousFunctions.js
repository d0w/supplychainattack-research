// Dangerous obfuscated payload
const secret = atob('cGFzc3dvcmQ6IHNlY3JldA==');

setInterval(function() {
    eval("console.log('Running eval code');");
}, 5000);

function executePayload() {
    Function("console.log('Executed via Function constructor')")();
}
