jest.mock("../../connect", () => jest.fn().mockResolvedValue());
jest.mock("../../model/user", () => ({
  findById: jest.fn(),
}));
jest.mock("../../model/passwordResetToken", () => ({
  findOneAndUpdate: jest.fn(),
  findOne: jest.fn(),
}));

const bcrypt = require("bcryptjs");
const User = require("../../model/user");
const PasswordResetToken = require("../../model/passwordResetToken");
const { resetPassword } = require("../../controller/auth");

describe("Password reset", () => {
  let req;
  let res;
  let next;
  const originalFetch = global.fetch;

  beforeEach(() => {
    req = {
      body: {
        token: "reset-token",
        newPassword: "NewPassword123!",
      },
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    next = jest.fn();
    jest.clearAllMocks();
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      text: async () => "",
    });
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  it("rejects short reset passwords without consuming the token", async () => {
    req.body.newPassword = "short";

    await resetPassword(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      message: "Password must be at least 8 characters",
    });
    expect(PasswordResetToken.findOneAndUpdate).not.toHaveBeenCalled();
    expect(User.findById).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it("resets the password when the token and new password are valid", async () => {
    const user = {
      email: "user@example.com",
      save: jest.fn().mockResolvedValue(),
    };
    PasswordResetToken.findOneAndUpdate.mockResolvedValue({ userId: "user-id" });
    User.findById.mockResolvedValue(user);
    jest.spyOn(bcrypt, "hash").mockResolvedValue("hashed-password");

    await resetPassword(req, res, next);

    expect(PasswordResetToken.findOneAndUpdate).toHaveBeenCalledWith(
      { token: "reset-token", used: false, expiresAt: { $gt: expect.any(Date) } },
      { $set: { used: true, usedAt: expect.any(Date) } },
      { new: true }
    );
    expect(user.password).toBe("hashed-password");
    expect(user.passwordChangedAt).toBeInstanceOf(Date);
    expect(user.save).toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      message: "Password reset successfully. Please log in with your new password.",
    });
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects a compromised reset password without consuming the token", async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      text: async () => "1E4C9B93F3F0682250B6CF8331B7EE68FD8:1",
    });
    req.body.newPassword = "password";

    await resetPassword(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      message: "This password has appeared in a data breach. Please choose a different password.",
    });
    expect(PasswordResetToken.findOneAndUpdate).not.toHaveBeenCalled();
    expect(User.findById).not.toHaveBeenCalled();
  });

  it("returns a temporary error for an unavailable breach check without consuming the token", async () => {
    global.fetch.mockRejectedValue(new Error("network unavailable"));

    await resetPassword(req, res, next);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      message: "Password security check is temporarily unavailable. Please try again later.",
    });
    expect(PasswordResetToken.findOneAndUpdate).not.toHaveBeenCalled();
    expect(User.findById).not.toHaveBeenCalled();
  });
});
