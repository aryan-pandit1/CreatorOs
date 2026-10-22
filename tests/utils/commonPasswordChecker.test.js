const { isCommonPassword } = require("../../utils/commonPasswordChecker");

describe("common password checker", () => {
  it("matches common passwords case-insensitively", () => {
    expect(isCommonPassword("PASSWORD")).toBe(true);
  });

  it("matches a known common password", () => {
    expect(isCommonPassword("password123")).toBe(true);
  });

  it("allows a password outside the common-password blocklist", () => {
    expect(isCommonPassword("CreatorOS-Unique-Password-2026")).toBe(false);
  });

  it("does not treat non-string input as a common password", () => {
    expect(isCommonPassword(null)).toBe(false);
    expect(isCommonPassword({ password: "password" })).toBe(false);
  });
});
