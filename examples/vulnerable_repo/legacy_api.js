import { unusedHelper, deadService, activeRoute } from './utils';
const child_process = require('child_process');

export function runDiagnostics(cmdInput) {
    // SECURITY: Command injection vulnerability
    child_process.exec(`ping -c 1 ${cmdInput}`, (error, stdout) => {
        if (error) {
            console.error(error);
        }
    });
}

export function fetchUserProfile(userId) {
    try {
        const url = "https://api.internal/v1/user/" + userId;
        return activeRoute(url);
    } catch (err) {
        // GAP: Silent catch block
    }
}

export function initiateTransfer() {
    // GAP: Unimplemented stub
    throw new Error("Not implemented: pending financial approval");
}
