=== TekSecurity – Firewall, Login Security, Two-Factor Authentication & Malware Scan ===
Contributors: tekzen, tarikulalways
Tags: security, firewall, two-factor-authentication, login-security, malware
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Firewall, malware scanner, two-factor authentication and brute-force login protection for WordPress — in plain English, not security jargon.

== Description ==

**TekSecurity is a complete WordPress security plugin that blocks hackers
before WordPress even loads.** It combines a web application firewall (WAF),
brute-force login protection, two-factor authentication (2FA), per-IP rate
limiting, malicious file upload blocking, plugin vulnerability shields, IP
blocklists and core file malware scanning — in one dashboard written in plain
English, not security jargon.

No account, no API key, no subscription, no connection to an outside service.
Install it, answer four questions, and your site is protected.

Most WordPress security plugins either overwhelm you with settings you daren't
touch, or hide everything behind a "protected" badge that tells you nothing.
TekSecurity does neither. Every screen explains what a protection does, what it
stopped this week, and what happens if you turn it off. When an attack is
blocked, you can open the request and read exactly what was sent, which rule
matched it, and why it was dangerous.

= Everything included =

* **WordPress firewall (WAF)** — blocks SQL injection, XSS, RCE, path
  traversal, privilege escalation and authentication bypass before WordPress
  loads.
* **Brute-force login protection** — per-IP lockouts, XML-RPC blocking and
  generic login errors.
* **Two-factor authentication (2FA)** — authenticator app (TOTP), email codes
  and backup codes, per user or per role.
* **Malware scanning** — daily core file integrity checks against the official
  WordPress.org checksums.
* **Plugin vulnerability shields** — virtual patching for known exploits in the
  plugins you already have installed.
* **Rate limiting** — per-IP, per-minute limits for login, REST API,
  `admin-ajax.php`, search and XML-RPC.
* **File upload protection** — blocks PHP backdoors, double extensions and
  malicious SVGs.
* **IP blocklist and allowlist** — single addresses or CIDR ranges.
* **Traffic log** — every blocked request, searchable, with a plain-language
  explanation of what the attacker was trying to do.
* **Email alerts and a weekly summary** — throttled so an attack cannot flood
  your inbox.

= Why site owners choose TekSecurity =

* **It blocks attacks before WordPress loads.** The firewall runs at
  `plugins_loaded`, so a SQL injection or remote code execution attempt is
  rejected with a 403 before your theme, your plugins or your database are ever
  touched.
* **Two views, one plugin.** *Simple* view uses plain language and safe
  defaults, for site owners. *Advanced* view adds rule IDs, matched payloads,
  per-rule block-or-log modes, custom rate limits and per-path rule exclusions,
  for developers and agencies. Switch any time — it is one click in the header.
* **Learning mode, so you never break your own site.** Run the firewall in
  Learning mode for a few days after a big change. It records everything it
  *would* have blocked without blocking anything, so you can spot false alarms
  before they cost you a customer.
* **No third-party requests from your admin.** The dashboard's icons and styles
  ship inside the plugin. Nothing about your site, your traffic or your visitors
  is sent anywhere.
* **It tells you when it is not helping.** If a protection is off, a plugin is
  exposed, or a setting is silently doing nothing on your site, the dashboard
  says so in the banner at the top instead of showing a green tick.

= WordPress firewall (WAF) =

The firewall inspects the URL, query string, POST body, cookies and headers of
every request against a signature set covering the attacks WordPress sites
actually receive:

* **SQL injection** — UNION-based, time-based blind, boolean-based, and reads
  against `wp_users`, `wp_options` or `information_schema`.
* **Cross-site scripting (XSS)** — event-handler injection, injected
  `<script>`, `<iframe>` and `<svg>` tags, and script URIs in parameters.
* **Authentication bypass** — forged REST nonces and tampered password-reset
  keys.
* **Privilege escalation** — requests that try to set a role to administrator,
  or change `default_role`, `users_can_register`, `siteurl` or `active_plugins`.
* **Exploit attempts** — path traversal, PHP object injection, remote code
  execution, and PHP stream wrappers such as `php://filter`.
* **Malicious requests** — probes for `.env`, `wp-config.php.bak`, `.git/`,
  `debug.log` and other sensitive files, known scanner user agents, and author
  enumeration via `?author=N`.

Each of the six firewall modules can be switched off independently, or set to
**Log only** so it records matches without blocking. The whole firewall has
three modes: **Protect**, **Learning** and **Off**.

Every rule carries a stable identifier such as `TS-SQLI-1003` or `TS-EXP-1102`,
so you can find it in the traffic log, exclude it on one path, and still keep it
running everywhere else.

= Brute-force login protection =

TekSecurity counts failed sign-in attempts per IP address and locks the address
out once it crosses your threshold.

* Threshold from 2 to 20 attempts, counted inside a 5-minute, 15-minute or
  1-hour window.
* Lockout for 15 minutes, 30 minutes, 1 hour or 24 hours.
* Optionally block anyone signing in as `admin` — though not when `admin` is a
  real account on your site, because that would lock out its owner. The plugin
  tells you when that is the case instead of leaving the setting silently inert.
* Optionally block XML-RPC sign-ins, which stops password guessing through
  `xmlrpc.php` and the `system.multicall` amplification trick.
* Login errors are made generic, so an attacker cannot learn which half of the
  credentials was correct.
* Locked-out addresses are listed on the Login protection screen with the
  username tried and the release time, and you can unlock any of them in a
  click.

= Two-factor authentication (2FA) =

Two-factor authentication means a stolen password on its own is not enough to
open an account.

* **Authenticator app** — standards-compliant TOTP (RFC 6238), so it works with
  Google Authenticator, 1Password, Authy, Microsoft Authenticator, Bitwarden and
  any other app that scans a QR code. The QR code is generated inside your
  browser; the secret is never sent to a third party.
* **Email codes** — a six-digit code mailed to the account address, valid for
  ten minutes, for people who will not install an app.
* **Backup codes** — ten single-use codes for when the phone is lost. They are
  stored hashed, never in plain text, and each one stops working the moment it
  is spent.
* **Per-user, by role.** Pick a role to load its users, then require two-factor
  for one person or for everyone in that role. It is not all-or-nothing.
* **A grace period you choose** — none, 3, 7 or 14 days — with a "Send reminder"
  button for anyone who has not finished setting it up.
* **Trusted devices** — optionally skip the code on a browser someone has
  already used, for 7 or 30 days, or never.

= Rate limiting =

Bots that scrape, spam or probe send far more requests than a real visitor.
TekSecurity applies a per-IP, per-minute limit to the paths that matter, and
picks the narrowest matching rule for each request:

* All requests, the login page, the REST API, `admin-ajax.php`, site search and
  XML-RPC each get their own limit.
* Three presets — **Relaxed** for busy stores and headless front-ends,
  **Balanced** for most sites, **Strict** for a site under active attack — or
  set any limit by hand in Advanced view.
* Over the limit, TekSecurity either throttles with a `429 Too Many Requests` or
  blocks for ten minutes. Your choice.
* Logged-in administrators can be exempted, so bulk edits, imports and WP-CLI
  work never trip a limit.

= Malicious file upload protection =

An uploaded PHP file is a backdoor. TekSecurity checks every upload — from the
media library, from contact forms, and from any plugin that uses the WordPress
upload API:

* Blocks dangerous extensions (`.php`, `.phtml`, `.phar`, `.exe`, `.sh`,
  `.htaccess` and more), and you can add your own.
* Catches **double extensions** such as `invoice.pdf.php` by checking every
  dotted segment, not just the last one.
* **Scans file contents** for PHP hidden inside an image or a document, so a
  `.jpg` that opens with `<?php` is rejected even though its extension is fine.
* **Sanitises SVG uploads**, stripping `<script>`, event handlers and
  `javascript:` URLs before the file is saved.
* Optionally applies all of the above to files sent by logged-out visitors
  through contact and checkout forms.

= Plugin vulnerability shields (virtual patching) =

The most common way a WordPress site is hacked is a known, unpatched plugin.
TekSecurity matches your installed plugins against an advisory feed and, for
those with a known exploit, blocks the exploit at the firewall — a **virtual
patch** — so you are protected in the window between disclosure and the moment
you can safely update.

The Plugin shields screen lists every installed plugin with its severity, the
issue, the version that fixes it, and a one-click **Update** button. Shields can
be toggled per plugin. The dashboard warns you about any plugin that is
vulnerable *and* has no shield covering it.

= IP blocklist and allowlist =

* **Blocklist** — addresses and CIDR ranges that cannot reach your site at all.
  Add one straight from a request in the traffic log.
* **Allowlist** — addresses that skip every firewall and rate-limit check. Put
  your office network here so you always have a way in.
* TekSecurity refuses to blocklist a range that covers your own address, so you
  cannot accidentally lock yourself out.

= Core file integrity and malware scanning =

Once a day, TekSecurity compares every WordPress core file against the checksums
WordPress.org publishes for your exact version and locale, and reports anything
**modified**, **missing**, or **added that core does not ship** — which is how
an injected backdoor in `wp-includes` gives itself away. Your themes, plugins
and uploads are left alone, so deleting a bundled theme is never reported as
tampering.

= Traffic log you can actually read =

Every blocked or logged request is recorded with its time, method, path, attack
type, source IP, matched rule and outcome. Search by IP, path, rule ID or attack
type; filter by blocked or logged; page through the results.

Open any row and TekSecurity explains, in one sentence and without jargon, what
the attacker was trying to do. In Advanced view the same panel shows the exact
method and URL, which parameter matched, the raw payload, the rule name and the
user agent — and offers **Block this IP**, **All from this IP** and **Exclude
rule here**.

= Email alerts and the weekly summary =

Choose alerts for **critical attacks only**, for **every block**, or **nothing
at all**. Critical attacks mean SQL injection, exploit attempts, plugin
exploits, privilege escalation and malicious uploads. Alerts are throttled to
one email per attack type per hour, so a sustained attack cannot flood your
inbox. A weekly summary covers what was blocked, which plugins need attention
and which addresses are locked out.

= Privacy =

TekSecurity stores the requests it blocks — including visitor IP addresses — in
a table on your own site, for 7, 30 or 90 days as you choose, after which they
are deleted automatically. Nothing is sent to us or to anyone else. The only
outbound requests the plugin ever makes are to WordPress.org for official core
checksums, and to the vulnerability advisory endpoint if you point it at one.

= Built for developers =

* A REST API under `teksecurity/v1`, guarded by `manage_options`.
* **11 filters:** `teksecurity_skip_firewall`,
  `teksecurity_firewall_candidates`, `teksecurity_ip_country`,
  `teksecurity_early_text`, `teksecurity_critical_types`,
  `teksecurity_alert_mail`, `teksecurity_virtual_patches`,
  `teksecurity_vulnerability_feed_url`, `teksecurity_bundled_advisories`,
  `teksecurity_integrity_ignored`, `teksecurity_integrity_is_core`.
* **8 actions:** `teksecurity_loaded`, `teksecurity_event_logged`,
  `teksecurity_request_blocked`, `teksecurity_ip_locked_out`,
  `teksecurity_integrity_scanned`, `teksecurity_2fa_enabled`,
  `teksecurity_2fa_reset`, `teksecurity_backup_code_used`.
* A PSR-4 style autoloader, no Composer dependency, and no vendor directory.
* A React admin built with `@wordpress/scripts`, fully translatable, with a
  `.pot` file covering every string.
* Uninstall removes every table, option, user meta key and scheduled job.

== Installation ==

= From your WordPress dashboard =

1. Go to **Plugins → Add New**.
2. Search for **TekSecurity**.
3. Click **Install Now**, then **Activate**.

= Uploading the ZIP =

1. Go to **Plugins → Add New → Upload Plugin**.
2. Choose `teksecurity.zip` and click **Install Now**.
3. Click **Activate Plugin**.

= By FTP =

1. Upload the `teksecurity` folder to `/wp-content/plugins/`.
2. Activate **TekSecurity** from the **Plugins** screen.

= After activating =

A four-question setup wizard opens. It asks which view you want, how traffic
reaches your site, whether to protect immediately or learn first, and where
alerts should go. You can take the recommended answers with **Skip setup**, and
change every one of them later under **TekSecurity → Settings**.

Two things are worth doing on day one:

1. Add your own IP or office range to the **allowlist**, so you always have a
   guaranteed way in.
2. Set **Visitor IP source** to match your hosting. If your site sits behind
   Cloudflare or another proxy and this is wrong, every visitor looks like one
   address and the firewall cannot tell them apart.

== Frequently Asked Questions ==

= Will TekSecurity slow down my site? =

No. The firewall runs on the request itself, before WordPress finishes loading,
and does pattern matching in memory — there is no HTTP call and no database read
on a clean request. The scans that do real work (core integrity, vulnerability
matching, log pruning) run on WP-Cron in the background, never on a page load.

= Will it lock me out of my own site? =

It is built not to. The allowlist skips every check, so put your address there
first. TekSecurity also refuses to blocklist a range covering your own IP, and
it never locks out a username that really exists on the site. If you are already
locked out, you can clear the lockout from the database or with WP-CLI.

= Does it work with Cloudflare, or behind a load balancer? =

Yes. Set **Visitor IP source** under Settings to `CF-Connecting-IP` for
Cloudflare or `X-Forwarded-For` for another proxy or CDN. The setup wizard asks
this on step two, because getting it wrong is the single most common way a
firewall ends up blocking a CDN instead of an attacker.

= A firewall rule is blocking something legitimate. What do I do? =

Open the request in the traffic log, switch to **Advanced** view, and use
**Exclude rule here**. That skips one rule on one path and leaves every other
rule running. For something broader, set the firewall to **Learning** mode while
you work it out — it keeps recording without blocking.

= Do I have to force two-factor authentication on everyone? =

No. You choose exactly who it applies to, one user or one role at a time, and
you give them a grace period — up to 14 days — to set it up. Nobody is locked
out overnight.

= What happens if a user loses their phone? =

They use one of their ten backup codes. If those are gone too, an administrator
can reset two-factor for that account from the Two-factor auth screen, and the
user sets it up again from scratch.

= Does this replace my backups? =

No, and nothing does. TekSecurity stops attacks and tells you when core files
change, but a security plugin is not a recovery plan. Keep taking backups.

= Is TekSecurity compatible with WooCommerce? =

Yes. WooCommerce roles such as Shop manager and Customer appear in the
two-factor role picker, `admin-ajax.php` has its own rate limit so checkout and
cart fragments are not throttled, and administrators can be exempted from rate
limits entirely so bulk imports keep working.

= Does it work on a site with no outbound internet access? =

Mostly. The firewall, login protection, two-factor authentication, rate
limiting, upload filtering and IP lists all work completely offline. Only core
integrity scanning (which fetches checksums from WordPress.org) and the
vulnerability advisory feed need outbound access.

= Is it GDPR friendly? =

TekSecurity stores visitor IP addresses for blocked requests, which is personal
data in the EU. You control the retention period (7, 30 or 90 days) and old
entries are deleted automatically. Nothing leaves your server, so there is no
third-party processor to declare.

= Does TekSecurity send any of my data to you? =

No. There is no account, no API key and no telemetry. Blocked requests are
stored in a table on your own site and deleted automatically when your retention
period expires. The only outbound requests the plugin ever makes are to
WordPress.org for official core checksums, and to the vulnerability advisory
endpoint if you point it at one.

= What happens to my data if I delete the plugin? =

Deleting TekSecurity removes everything it created: all six database tables, all
its options, every two-factor user meta key and all its scheduled jobs.
Deactivating without deleting leaves your data and settings intact.

== Screenshots ==

1. The dashboard — a plain-language status banner, this week's numbers, blocked
   requests by day, attack types, latest attacks and all ten protections at a
   glance.
2. The traffic log in Advanced view, with the request drawer open showing the
   matched rule, the exact payload and the user agent.
3. Firewall settings — Protect, Learning or Off, plus per-rule block or
   log-only modes and rule exclusions.
4. Two-factor authentication — add users by role, choose sign-in methods, and
   track who has finished setting up.
5. The authenticator enrolment modal, with a QR code generated in the browser.
6. Plugin shields, showing which plugins are vulnerable, shielded or exposed.
7. Dark mode, supported on every screen.

== Source Code ==

The admin interface is written in React and compiled with
`@wordpress/scripts`. The readable, unminified sources live in the `src/`
directory of the development repository, and `build/` is the compiled output
shipped in the plugin.

To build it yourself:

`npm install && npm run build`

The full source code: https://github.com/tarikulalways/teksecurity

== Changelog ==

= 1.0.0 — 12 October 2026 =

First public release.

**Firewall**

* Web application firewall running at `plugins_loaded`, ahead of theme and
  plugin code, returning `403` with an `X-TekSecurity` header on a block.
* Signature coverage for SQL injection (`TS-SQLI-*`), cross-site scripting
  (`TS-XSS-*`), authentication bypass (`TS-AUTH-*`), privilege escalation
  (`TS-PRIV-*`), exploit attempts (`TS-EXP-*`) and malicious requests
  (`TS-MAL-*`).
* Three firewall modes: Protect, Learning and Off.
* Per-module on/off and per-module Block or Log-only modes.
* Per-path rule exclusions, addable straight from a request in the traffic log.
* Inspection of the path, query string, POST body, cookies, user agent and
  parameter-name/value pairs.

**Login protection**

* Per-IP failed-login counting with a configurable threshold (2–20), counting
  window (5, 15 or 60 minutes) and lockout duration (15, 30, 60 or 1440
  minutes).
* Optional blocking of sign-ins as `admin`, skipped automatically when `admin`
  is a real account so its owner is never locked out.
* Optional XML-RPC sign-in blocking.
* Generic login error messages, so a failed attempt reveals nothing.
* A live lockout list with one-click unlock, and automatic purging of expired
  lockouts.

**Two-factor authentication**

* RFC 6238 TOTP with a browser-generated QR code and a manual entry key.
* Email one-time codes with a ten-minute expiry.
* Ten single-use backup codes, stored hashed with the WordPress password hasher.
* Per-user and per-role enrolment, a grace period of none/3/7/14 days, and
  emailed setup reminders.
* Trusted devices for 7 or 30 days, or never.
* Administrator reset of any user's two-factor setup.
* Two-factor status shown on the WordPress user profile screen.

**Rate limiting**

* Per-IP, per-minute limits for all requests, the login page, the REST API,
  `admin-ajax.php`, site search and XML-RPC, with the narrowest matching rule
  winning.
* Relaxed, Balanced and Strict presets, plus hand-set limits in Advanced view.
* Throttle with `429` or block for ten minutes.
* Optional exemption for logged-in administrators.

**File upload protection**

* Blocked extension list, editable, applied to every dotted segment so
  `invoice.pdf.php` is caught.
* Content scanning that finds PHP hidden inside images and documents.
* SVG sanitisation that strips scripts, event handlers and `javascript:` URLs.
* Optional enforcement on uploads from logged-out visitors.
* Blocked extensions also removed from the allowed MIME map.

**Plugin vulnerability shields**

* Twice-daily matching of installed plugins against an advisory feed.
* Virtual patches that block known exploits at the firewall.
* Per-plugin shield toggles and one-click updating to the fixed version.
* Dashboard warning for any plugin that is vulnerable with no shield.

**IP lists**

* Blocklist and allowlist, both accepting single addresses and CIDR ranges.
* Allowlisted addresses skip every firewall and rate-limit check.
* Self-lockout protection when adding a blocklist range.

**Core file integrity**

* Daily comparison against the official WordPress.org checksums for your exact
  version and locale.
* Reports modified, missing and unexpected core files, scoped to `wp-admin`,
  `wp-includes` and the root PHP files so removing a bundled theme is never
  reported as tampering.

**Traffic log and alerts**

* Searchable, filterable, paginated log of every blocked and logged request.
* Request drawer with a plain-language explanation, and the full technical
  detail in Advanced view.
* Email alerts for critical attacks or every block, throttled to one per attack
  type per hour.
* Weekly summary email.
* Automatic log pruning on a 7, 30 or 90-day retention setting.

**Admin**

* React admin with ten screens, a four-step setup wizard, and Simple and
  Advanced views.
* Dark mode on every screen, remembered per browser.
* Visitor IP source setting for direct, Cloudflare and generic proxy hosting.
* No third-party requests: icons and styles ship with the plugin.
* Fully translatable, with a `.pot` file covering every string.

**Developer**

* REST API under `teksecurity/v1`, guarded by `manage_options`.
* 11 filters and 8 actions for extending every module.
* Clean uninstall of all tables, options, user meta and scheduled jobs.

== Upgrade Notice ==

= 1.0.0 =
First release of TekSecurity. After activating, run the four-question setup
wizard, then add your own IP to the allowlist and check the Visitor IP source
setting matches your hosting.
