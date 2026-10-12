import { describe, it, expect } from "vitest";
import { REDACTED, redactCommand } from "../../src/session/redact";

// Las claves de prueba se arman por partes para que ningún escáner de
// secretos las tome por reales.
const fake = (prefix: string, length = 40) => prefix + "a1B2c3D4".repeat(Math.ceil(length / 8)).slice(0, length);

describe("redactCommand: tapa secretos", () => {
  const cases: [string, string][] = [
    // Variables de entorno
    ["export API_KEY=abc123", `export API_KEY=${REDACTED}`],
    ['export OPENAI_API_KEY="abc 123"', `export OPENAI_API_KEY=${REDACTED}`],
    ["GITHUB_TOKEN=abc npm publish", `GITHUB_TOKEN=${REDACTED} npm publish`],
    ["DB_PASSWORD='x y' ./run.sh", `DB_PASSWORD=${REDACTED} ./run.sh`],
    ["export aws_secret_access_key=abc", `export aws_secret_access_key=${REDACTED}`],
    ["set -x ANTHROPIC_API_KEY abc123", `set -x ANTHROPIC_API_KEY ${REDACTED}`],
    ['$env:API_KEY = "abc"', `$env:API_KEY = ${REDACTED}`],
    // Headers
    ['curl -H "Authorization: Bearer abc.def" https://api.x.dev', `curl -H "Authorization: Bearer ${REDACTED}" https://api.x.dev`],
    ["curl -H 'X-Api-Key: abc' https://api.x.dev", `curl -H 'X-Api-Key: ${REDACTED}' https://api.x.dev`],
    ['curl -H "authorization:abc" x', `curl -H "authorization:${REDACTED}" x`],
    // Flags
    ["gh auth login --token abc", `gh auth login --token ${REDACTED}`],
    ["tool --api-key=abc run", `tool --api-key=${REDACTED} run`],
    ['psql --password "a b"', `psql --password ${REDACTED}`],
    ["curl -u ana:hunter2 https://x.dev", `curl -u ana:${REDACTED} https://x.dev`],
    ["mysql -u root -phunter2 db", `mysql -u root -p${REDACTED} db`],
    // URLs
    ["git clone https://ana:hunter2@github.com/a/b", `git clone https://ana:${REDACTED}@github.com/a/b`],
    ["psql postgres://app:hunter2@db:5432/app", `psql postgres://app:${REDACTED}@db:5432/app`],
    ["curl 'https://x.dev/a?access_token=abc&page=2'", `curl 'https://x.dev/a?access_token=${REDACTED}&page=2'`],
  ];

  it.each(cases)("%s", (input, expected) => {
    expect(redactCommand(input)).toBe(expected);
  });

  it("tapa claves con formato conocido aunque no tengan nombre", () => {
    const tokens = [
      fake("sk-ant-api03-"),
      fake("sk-proj-"),
      fake("gh" + "p_", 36),
      fake("github_" + "pat_", 60),
      fake("glpat-", 20),
      fake("xo" + "xb-", 30),
      "AKIA" + "IOSFODNN7EXAMPLE",
      fake("AI" + "za", 35),
      fake("sk_" + "live_", 24),
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlLXZhbHVl",
    ];
    for (const token of tokens) {
      const out = redactCommand(`echo ${token} | some-cli login`);
      expect(out, token).toBe(`echo ${REDACTED} | some-cli login`);
    }
  });
});

describe("redactCommand: deja intactos los comandos comunes", () => {
  const untouched = [
    "npm test -- login",
    "git commit -m 'fix: refresh token on 401'",
    "git checkout 3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
    "mkdir -p src/auth",
    "docker run -p 8080:80 nginx",
    "git add -p",
    "ls -la ~/.ssh",
    "cat .env.example",
    "echo $API_KEY | docker login --password-stdin -u ana",
    "gh auth login --with-token < token.txt",
    "kubectl create secret generic app --from-file=./creds",
    "cd $PWD/src && make",
    "curl https://example.com/api?page=2",
    "claude",
  ];

  it.each(untouched)("%s", (command) => {
    expect(redactCommand(command)).toBe(command);
  });
});
