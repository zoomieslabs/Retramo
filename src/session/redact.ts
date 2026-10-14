/**
 * Tapa secretos en una línea de comando antes de guardarla o mostrarla.
 *
 * La terminal es donde más fácil se escribe una clave a mano (`export
 * API_KEY=...`, un `curl` con `Authorization`), y esos comandos terminan en
 * el JSON de la sesión y, con el resumen activo, en el proveedor. Se prefiere
 * tapar de más: un comando con un `***` de sobra sigue sirviendo para
 * recordar qué hacías; una clave filtrada no tiene arreglo.
 */
export const REDACTED = "***";

// Nombres de variables, flags, headers y parámetros que suelen llevar secretos.
const SECRET_WORD = String.raw`(?:key|token|secret|pass(?:word|wd|phrase)?|pwd|credentials?|auth|private|session|cookie|dsn|signature)`;
// Un valor entre comillas, o una palabra hasta el próximo espacio u operador.
const QUOTED_OR_WORD = String.raw`(?:"[^"]*"|'[^']*'|[^\s"'&;|<>]+)`;

// Formatos conocidos de claves: se tapan donde aparezcan.
const TOKEN_SHAPES: RegExp[] = [
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}/g, // OpenAI, Anthropic
  /\b(?:gh[pousr])_[A-Za-z0-9]{20,}/g, // GitHub
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g, // GitLab
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, // Slack
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, // AWS
  /\bAIza[0-9A-Za-z_-]{35}/g, // Google
  /\bnpm_[A-Za-z0-9]{36}/g,
  /\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}/g, // Stripe
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, // JWT
];

type Replacement = string | ((match: string, ...groups: string[]) => string);

const RULES: [RegExp, Replacement][] = [
  // Asignación de una variable con nombre sensible (bash, zsh, `export`, prefijo de un comando).
  [new RegExp(String.raw`\b([A-Za-z_][A-Za-z0-9_]*${SECRET_WORD}[A-Za-z0-9_]*)=${QUOTED_OR_WORD}`, "gi"), `$1=${REDACTED}`],
  // La misma asignación en fish, con `set`.
  [new RegExp(String.raw`\b(set\s+(?:-\w+\s+)*[A-Za-z0-9_]*${SECRET_WORD}[A-Za-z0-9_]*\s+)${QUOTED_OR_WORD}`, "gi"), `$1${REDACTED}`],
  // La misma asignación en PowerShell, con `$env:`.
  [new RegExp(String.raw`(\$env:[A-Za-z0-9_]*${SECRET_WORD}[A-Za-z0-9_]*\s*=\s*)${QUOTED_OR_WORD}`, "gi"), `$1${REDACTED}`],
  // Headers de autorización o de clave. Se conserva el esquema (Bearer, Basic).
  [
    new RegExp(String.raw`\b((?:proxy-)?authorization|[\w-]*${SECRET_WORD}[\w-]*)(\s*:\s*)(?:(bearer|basic|token|bot|digest)\s+)?[^\s"']+`, "gi"),
    (_m, name: string, sep: string, scheme?: string) => `${name}${sep}${scheme ? `${scheme} ` : ""}${REDACTED}`,
  ],
  // Flags con nombre sensible, con espacio o con `=`. No los que nombran un archivo o stdin.
  [
    new RegExp(String.raw`(\s--?[\w-]*${SECRET_WORD}[\w-]*(?<!-file|-stdin|-path|-env))(=|\s+)(?![-<>|&;])${QUOTED_OR_WORD}`, "gi"),
    `$1$2${REDACTED}`,
  ],
  // Usuario y contraseña pasados con `-u` o `--user`: se tapa lo que sigue a los dos puntos.
  [/(\s(?:-u|--user)[\s=]*["']?[^\s:"']+):[^\s"']+/g, `$1:${REDACTED}`],
  // Credenciales dentro de una URL: se tapa la contraseña antes de la arroba.
  [/(\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@"']+):[^/\s@"']+@/gi, `$1:${REDACTED}@`],
  // Parámetros de una URL con nombre sensible.
  [new RegExp(String.raw`([?&][\w-]*(?:${SECRET_WORD}|sig|key)[\w-]*=)[^&\s"'#]+`, "gi"), `$1${REDACTED}`],
];

// La contraseña pegada a `-p`: solo significa eso en los clientes de MySQL.
const MYSQL = /\b(?:mysql|mariadb|mysqldump|mysqladmin)\b/;
const MYSQL_PASSWORD = /(\s-p)[^\s]+/g;

export function redactCommand(command: string): string {
  let out = command;
  for (const shape of TOKEN_SHAPES) {
    out = out.replace(shape, REDACTED);
  }
  for (const [pattern, replacement] of RULES) {
    out = typeof replacement === "string" ? out.replace(pattern, replacement) : out.replace(pattern, replacement);
  }
  if (MYSQL.test(out)) {
    out = out.replace(MYSQL_PASSWORD, `$1${REDACTED}`);
  }
  return out;
}
