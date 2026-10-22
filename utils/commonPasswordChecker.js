// This intentionally small baseline is maintained in source so password
// validation does not depend on a bundled third-party wordlist. Keep entries
// to well-known weak passwords rather than importing an unverified dataset.
const commonPasswords = new Set([
    "12345678",
    "123456789",
    "1234567890",
    "abc12345",
    "admin",
    "baseball",
    "dragon",
    "football",
    "iloveyou",
    "letmein",
    "master",
    "monkey",
    "password",
    "password1",
    "password123",
    "princess",
    "qwerty123",
    "sunshine",
    "trustno1",
    "welcome",
    "whatever",
]);

function isCommonPassword(password) {
    if (typeof password !== "string") {
        return false;
    }

    return commonPasswords.has(password.toLowerCase());
}

module.exports = { isCommonPassword };
