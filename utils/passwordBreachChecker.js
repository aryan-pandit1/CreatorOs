const crypto = require("crypto");

const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range";
const HIBP_TIMEOUT_MS = 5000;
const HIBP_USER_AGENT = "CreatorOS/1.0 (password security check)";

class PasswordBreachCheckError extends Error {
  constructor(message, { cause } = {}) {
    super(message, { cause });
    this.name = "PasswordBreachCheckError";
    this.code = "PASSWORD_BREACH_CHECK_UNAVAILABLE";
  }
}

function sha1(password) {
  return crypto.createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
}

function responseContainsHashSuffix(responseBody, hashSuffix) {
  return responseBody.split(/\r?\n/).some((line) => {
    const [suffix] = line.split(":", 1);
    return suffix?.toUpperCase() === hashSuffix;
  });
}

/**
 * Checks a password against HIBP's Pwned Passwords k-anonymity endpoint.
 * Only the first five SHA-1 characters leave this process; the full hash and
 * plaintext password remain local.
 */
async function isPasswordCompromised(password) {
  const passwordHash = sha1(password);
  const hashPrefix = passwordHash.slice(0, 5);
  const hashSuffix = passwordHash.slice(5);

  let response;
  try {
    response = await fetch(`${HIBP_RANGE_URL}/${hashPrefix}`, {
      headers: {
        "User-Agent": HIBP_USER_AGENT,
        "Add-Padding": "true",
      },
      signal: AbortSignal.timeout(HIBP_TIMEOUT_MS),
    });
  } catch (error) {
    throw new PasswordBreachCheckError(
      "Password security check is temporarily unavailable. Please try again later.",
      { cause: error },
    );
  }

  if (!response.ok) {
    throw new PasswordBreachCheckError(
      "Password security check is temporarily unavailable. Please try again later.",
    );
  }

  try {
    return responseContainsHashSuffix(await response.text(), hashSuffix);
  } catch (error) {
    throw new PasswordBreachCheckError(
      "Password security check is temporarily unavailable. Please try again later.",
      { cause: error },
    );
  }
}

module.exports = {
  HIBP_RANGE_URL,
  HIBP_TIMEOUT_MS,
  HIBP_USER_AGENT,
  PasswordBreachCheckError,
  isPasswordCompromised,
};
