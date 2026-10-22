const crypto = require("crypto");
const {
  HIBP_RANGE_URL,
  HIBP_USER_AGENT,
  PasswordBreachCheckError,
  isPasswordCompromised,
} = require("../../utils/passwordBreachChecker");

describe("password breach checker", () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.clearAllMocks();
  });

  it("sends only the five-character SHA-1 prefix and detects a compromised password", async () => {
    const password = "PlaintextSecret42!";
    const passwordHash = crypto.createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      text: async () => `${passwordHash.slice(5)}:4663`,
    });

    await expect(isPasswordCompromised(password)).resolves.toBe(true);

    expect(global.fetch).toHaveBeenCalledWith(
      `${HIBP_RANGE_URL}/${passwordHash.slice(0, 5)}`,
      expect.objectContaining({
        headers: {
          "User-Agent": HIBP_USER_AGENT,
          "Add-Padding": "true",
        },
        signal: expect.any(AbortSignal),
      }),
    );
    const requestedUrl = global.fetch.mock.calls[0][0];
    expect(new URL(requestedUrl).pathname).toBe(`/range/${passwordHash.slice(0, 5)}`);
    expect(requestedUrl).not.toContain(password);
    expect(requestedUrl).not.toContain(passwordHash);
  });

  it("allows a password whose suffix is absent from the response", async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      text: async () => "00000000000000000000000000000000000:0",
    });

    await expect(isPasswordCompromised("UniquePassword123!")).resolves.toBe(false);
  });

  it("fails closed when the range request times out or fails", async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error("socket closed"));

    await expect(isPasswordCompromised("UniquePassword123!")).rejects.toBeInstanceOf(
      PasswordBreachCheckError,
    );
  });
});
