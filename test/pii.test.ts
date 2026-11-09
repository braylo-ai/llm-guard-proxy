import { describe, expect, it } from "vitest";
import { detectPii, ibanValid, luhnValid } from "../src/pii";

const types = (t: string) => detectPii(t).map((e) => e.type);

describe("pii detectors", () => {
  it("luhn validates published test card numbers and rejects off-by-one", () => {
    expect(luhnValid("4111111111111111")).toBe(true);
    expect(luhnValid("4111111111111112")).toBe(false);
  });
  it("detects cards with spaces/dashes only when Luhn + issuer prefix pass", () => {
    expect(types("card 4111-1111-1111-1111")).toEqual(["CREDIT_CARD"]);
    expect(types("invoice 1234 5678 9012 3456")).toEqual([]);
  });
  it("validates IBAN mod-97 and country length", () => {
    expect(ibanValid("GB82WEST12345698765432")).toBe(true);
    expect(ibanValid("GB82WEST12345698765433")).toBe(false);
    expect(ibanValid("DE8937040044053201300")).toBe(false); // wrong length
  });
  it("rejects SSNs in never-issued ranges", () => {
    expect(types("ssn 512-38-4471")).toEqual(["SSN"]);
    expect(types("000-12-3456 666-12-3456 912-34-5678")).toEqual([]);
  });
  it("detects emails including RFC apostrophes", () => {
    expect(detectPii("to o'neil@example.com now")[0]?.value).toBe("o'neil@example.com");
    expect(types("user@localhost")).toEqual([]);
  });
  it("detects NANP and international phones but not bare numbers", () => {
    expect(types("call (312) 555-0142")).toEqual(["PHONE"]);
    expect(types("+44 20 7946 0958")).toEqual(["PHONE"]);
    expect(types("we have 3125550142 widgets")).toEqual([]);
    expect(types("text me 3125550142")).toEqual(["PHONE"]);
  });
  it("detects vendor secrets and high-entropy assignments, not low-entropy ones", () => {
    expect(types("key AKIAIOSFODNN7EXAMPLE")).toEqual(["SECRET"]);
    expect(types("client_secret: 9fK2mQ7xL4pR8vN1")).toEqual(["SECRET"]);
    expect(types("password: hunter2")).toEqual([]);
  });
  it("detects US street addresses and PO boxes", () => {
    expect(detectPii("at 221 N Clark St, Chicago, IL 60601.")[0]?.value).toBe("221 N Clark St, Chicago, IL 60601");
    expect(types("P.O. Box 4417")).toEqual(["ADDRESS"]);
    expect(types("I walked 5 miles")).toEqual([]);
  });
  it("respects allowlist values and @domain entries", () => {
    expect(detectPii("ops@acme.example", undefined, ["@acme.example"])).toEqual([]);
    expect(detectPii("x@other.example", undefined, ["@acme.example"]).length).toBe(1);
  });
  it("resolves overlaps by priority (secret wins over phone digits inside it)", () => {
    const e = detectPii("Bearer abcdefghij3125550142klmnopqrstu");
    expect(e.map((x) => x.type)).toEqual(["SECRET"]);
  });
});
