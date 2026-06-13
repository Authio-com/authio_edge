import { describe, expect, it } from "vitest";
import { EdgeAuth } from "../src/index";

describe("EdgeAuth", () => {
  it("requires apiUrl", () => {
    expect(() => new EdgeAuth({ apiUrl: "" })).toThrow(/apiUrl/);
  });

  it("constructs with apiUrl", () => {
    const e = new EdgeAuth({ apiUrl: "https://api.authio.com" });
    expect(e).toBeDefined();
  });

  it("verifies invalid tokens to null", async () => {
    const e = new EdgeAuth({ apiUrl: "https://api.test" });
    expect(await e.verify("")).toBeNull();
    expect(await e.verify("not.a.jwt")).toBeNull();
  });
});
