import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const base = "https://netwatch-kohl.vercel.app/";
const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
const robots = await readFile(new URL("../robots.txt", import.meta.url), "utf8");
const sitemap = await readFile(new URL("../sitemap.xml", import.meta.url), "utf8");
const llms = await readFile(new URL("../llms.txt", import.meta.url), "utf8");

test("production head has one canonical and consistent social metadata", () => {
  assert.match(html, new RegExp(`<link rel="canonical" href="${base.replace(/[.*+?^${}()|[\]\\]/g, "\\\\$&")}">`));
  assert.equal((html.match(/rel="canonical"/g) ?? []).length, 1);
  assert.match(html, /property="og:url" content="https:\/\/netwatch-kohl\.vercel\.app\//);
  assert.match(html, /name="twitter:card" content="summary"/);
  assert.match(html, /<title>NETWATCH NG/);
});

test("JSON-LD identifies the website and software without unsupported product claims", () => {
  const match = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  assert.ok(match, "JSON-LD block exists");
  const graph = JSON.parse(match[1]);
  assert.equal(graph["@context"], "https://schema.org");
  const software = graph["@graph"].find((node) => node["@type"] === "SoftwareApplication");
  assert.ok(software);
  assert.equal(software.url, base);
  assert.equal(software.operatingSystem, "Linux");
  assert.match(software.description, /does not crack Wi-Fi keys/i);
  assert.doesNotMatch(software.description, /HTB queue shaping is supported/i);
});

test("robots and sitemap expose only the public product page", () => {
  assert.match(robots, /User-agent: \*/);
  assert.match(robots, /Allow: \/\s/);
  assert.match(robots, /Sitemap: https:\/\/netwatch-kohl\.vercel\.app\/sitemap\.xml/);
  assert.match(sitemap, /<loc>https:\/\/netwatch-kohl\.vercel\.app\/<\/loc>/);
  assert.doesNotMatch(sitemap, /preview|localhost|api\//i);
});

test("llms.txt contains documented capabilities and product limitations", () => {
  assert.match(llms, /networks you own or are authorized to administer/i);
  assert.match(llms, /does not crack Wi-Fi keys/i);
  assert.match(llms, /packet policing/i);
  assert.match(llms, /does not automatically update itself/i);
});
