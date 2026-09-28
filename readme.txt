=== TekSecurity ===
Contributors: teksecurity
Tags: security, firewall, two-factor, login, malware
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Firewall, login protection, two-factor authentication, plugin vulnerability shields and file integrity monitoring, in one plain-language dashboard.

== Description ==

TekSecurity inspects every request before WordPress finishes loading and stops
the ones that match an attack pattern. What it blocked, and why, is written to a
searchable traffic log you can read without being a security engineer.

The admin has two views. **Simple** explains each protection in plain language
and ships with settings that suit most sites. **Advanced** adds rule IDs,
matched payloads, per-rule block or log-only modes, custom rate limits and
per-path rule exclusions.

= What it protects =

* **Firewall** — SQL injection, cross-site scripting, authentication bypass,
  privilege escalation, path traversal, remote code execution, PHP object
  injection, scanners and probes for files like `.env` or `wp-config` backups.
  Run it in Protect mode, or in Learning mode for a few days after a big site
  change so you can spot false alarms before anything is blocked.
* **Login protection** — locks out an IP that keeps guessing passwords on
  `wp-login.php` or XML-RPC, with a configurable threshold, counting window and
  lockout duration.
* **Two-factor authentication** — a one-time code after the password, from an
  authenticator app or by email, with ten single-use backup codes and optional
  trusted devices. You choose which users it applies to, role by role.
* **Rate limiting** — per-IP request limits for the site, the login page, the
  REST API, admin-ajax, search and XML-RPC. Throttle with a 429, or block.
* **File uploads** — rejects blocked extensions, catches double extensions such
  as `invoice.pdf.php`, finds PHP hidden inside images and documents, and strips
  scripts out of SVG files before they are saved.
* **Plugin shields** — matches your installed plugins against an advisory feed
  and virtually patches known exploits until you can update.
* **IP lists** — a blocklist and an allowlist, both accepting CIDR ranges.
* **File integrity** — compares WordPress core against the checksums
  WordPress.org publishes for your exact version, and reports anything modified,
  missing or added.
* **Alerts** — email for critical attacks or every block, plus a weekly summary.

= Privacy =

TekSecurity stores the requests it blocks, including the visitor's IP address,
in a table on your own site, for as long as the retention setting says. Nothing
is sent anywhere else. The admin makes no third-party requests: its icons and
fonts ship with the plugin.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/teksecurity`, or install it through
   the Plugins screen.
2. Activate it.
3. Answer the four setup questions. You can change every answer later under
   TekSecurity → Settings.

== Frequently Asked Questions ==

= Will it lock me out? =

The allowlist skips every firewall check, so add your office IP there first if
you want a guaranteed way in. TekSecurity also refuses to blocklist a range that
covers your own address, and it never locks out a username that really exists on
the site.

= My site is behind Cloudflare. Will it block the CDN instead of the attacker? =

Only if it is reading the wrong header. Set *Visitor IP source* under Settings
to match how traffic reaches your site; the setup wizard asks this on step two.

= A rule is blocking something legitimate. =

Open the request in the traffic log and use **Exclude rule here** in Advanced
view. That skips just that rule on just that path, leaving every other rule in
place. For a wider problem, switch the firewall to Learning mode while you work
it out.

= Does it work with no outbound network access? =

The firewall, login protection, two-factor, rate limiting, uploads and IP lists
all work entirely offline. Integrity scanning needs to reach WordPress.org for
the official checksums, and the vulnerability feed needs to reach its endpoint.

== Changelog ==

= 1.0.0 =
* First release.
