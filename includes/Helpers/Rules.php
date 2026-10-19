<?php
/**
 * Firewall signature set and attack-type metadata.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Helpers;

defined( 'ABSPATH' ) || exit;

/**
 * The rules the firewall runs against every request.
 */
class Rules {

	/**
	 * Attack types shown in the admin, with the plain-language explanation
	 * the traffic-log drawer prints.
	 *
	 * @return array
	 */
	public static function types() {
		return array(
			'sqli'      => array(
				'label'   => __( 'SQL injection', 'teksecurity' ),
				'module'  => 'sqli',
				'explain' => __( 'Someone typed database commands into a URL or form field, trying to read or change your database. Your data was not touched.', 'teksecurity' ),
			),
			'xss'       => array(
				'label'   => __( 'XSS', 'teksecurity' ),
				'module'  => 'xss',
				'explain' => __( 'Someone tried to plant code that would run in your visitors’ browsers, for example to steal logged-in sessions.', 'teksecurity' ),
			),
			'auth'      => array(
				'label'   => __( 'Auth bypass', 'teksecurity' ),
				'module'  => 'auth',
				'explain' => __( 'Someone tried to act as a logged-in user without a valid login, using a forged or reused security token.', 'teksecurity' ),
			),
			'priv'      => array(
				'label'   => __( 'Privilege escalation', 'teksecurity' ),
				'module'  => 'priv',
				'explain' => __( 'A request tried to give an account more power than it has, such as turning a customer into an administrator.', 'teksecurity' ),
			),
			'plugin'    => array(
				'label'   => __( 'Plugin exploit', 'teksecurity' ),
				'module'  => 'plugin',
				'explain' => __( 'Someone targeted a known weakness in one of your installed plugins. A virtual patch stopped it before the plugin saw the request.', 'teksecurity' ),
			),
			'upload'    => array(
				'label'   => __( 'Malicious upload', 'teksecurity' ),
				'module'  => 'upload',
				'explain' => __( 'Someone tried to upload a file that could run code on your server. The file was rejected and never saved.', 'teksecurity' ),
			),
			'brute'     => array(
				'label'   => __( 'Brute force', 'teksecurity' ),
				'module'  => 'brute',
				'explain' => __( 'This IP kept guessing passwords on your login page. It was locked out after too many failed attempts.', 'teksecurity' ),
			),
			'rate'      => array(
				'label'   => __( 'Rate limit', 'teksecurity' ),
				'module'  => 'rate',
				'explain' => __( 'This IP sent far more requests than a normal visitor, so it was slowed down to protect your site’s speed.', 'teksecurity' ),
			),
			'malicious' => array(
				'label'   => __( 'Malicious request', 'teksecurity' ),
				'module'  => 'malicious',
				'explain' => __( 'An automated scanner probed your site for private files or used a known attack tool.', 'teksecurity' ),
			),
			'exploit'   => array(
				'label'   => __( 'Exploit attempt', 'teksecurity' ),
				'module'  => 'exploit',
				'explain' => __( 'Someone tried to trick your server into reading system files or running their code.', 'teksecurity' ),
			),
		);
	}

	/**
	 * The ten protection modules, in the order the dashboard lists them.
	 *
	 * @return array
	 */
	public static function modules() {
		return array(
			array(
				'key'   => 'malicious',
				'name'  => __( 'Malicious requests', 'teksecurity' ),
				'icon'  => 'ph-robot',
				'page'  => 'firewall',
				'desc'  => __( 'Stops scanners, known attack tools and probes for files like .env or wp-config backups.', 'teksecurity' ),
			),
			array(
				'key'  => 'exploit',
				'name' => __( 'Exploit protection', 'teksecurity' ),
				'icon' => 'ph-bug',
				'page' => 'firewall',
				'desc' => __( 'Stops path traversal, remote code execution and PHP object injection.', 'teksecurity' ),
			),
			array(
				'key'  => 'sqli',
				'name' => __( 'SQL injection', 'teksecurity' ),
				'icon' => 'ph-database',
				'page' => 'firewall',
				'desc' => __( 'Checks URLs, form fields and cookies for database commands.', 'teksecurity' ),
			),
			array(
				'key'  => 'xss',
				'name' => __( 'Cross-site scripting (XSS)', 'teksecurity' ),
				'icon' => 'ph-code',
				'page' => 'firewall',
				'desc' => __( 'Blocks code injected into comments, forms and URLs.', 'teksecurity' ),
			),
			array(
				'key'  => 'auth',
				'name' => __( 'Authentication bypass', 'teksecurity' ),
				'icon' => 'ph-key',
				'page' => 'firewall',
				'desc' => __( 'Rejects forged nonces, tampered password-reset keys and cookie tricks.', 'teksecurity' ),
			),
			array(
				'key'  => 'priv',
				'name' => __( 'Privilege escalation', 'teksecurity' ),
				'icon' => 'ph-user-gear',
				'page' => 'firewall',
				'desc' => __( 'Blocks role changes and option updates by users who aren’t allowed to make them.', 'teksecurity' ),
			),
			array(
				'key'  => 'plugin',
				'name' => __( 'Plugin exploit shields', 'teksecurity' ),
				'icon' => 'ph-plug',
				'page' => 'plugins',
			),
			array(
				'key'  => 'upload',
				'name' => __( 'File-upload protection', 'teksecurity' ),
				'icon' => 'ph-upload-simple',
				'page' => 'uploads',
			),
			array(
				'key'  => 'brute',
				'name' => __( 'Brute-force protection', 'teksecurity' ),
				'icon' => 'ph-lock-key',
				'page' => 'login',
			),
			array(
				'key'  => 'rate',
				'name' => __( 'Rate limiting', 'teksecurity' ),
				'icon' => 'ph-gauge',
				'page' => 'ratelimit',
			),
		);
	}

	/**
	 * Signatures, grouped by the firewall module that owns them.
	 *
	 * Each signature is:
	 *   id      Rule identifier surfaced in the admin.
	 *   name    Human readable rule name.
	 *   pattern PCRE, run against the decoded candidate value.
	 *   scope   Which parts of the request to test: path, query, body, cookie, headers.
	 *
	 * @return array
	 */
	public static function signatures() {
		return array(
			'sqli'      => array(
				array(
					'id'      => 'TS-SQLI-1003',
					'name'    => 'UNION-based SQL injection',
					'pattern' => '/\bunion\b[\s\/\*\(\)]*(all[\s\/\*]*)?\bselect\b/i',
					'scope'   => array( 'query', 'body', 'cookie' ),
				),
				array(
					'id'      => 'TS-SQLI-1011',
					'name'    => 'Time-based blind SQL injection',
					'pattern' => '/\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i',
					'scope'   => array( 'query', 'body', 'cookie' ),
				),
				array(
					'id'      => 'TS-SQLI-1018',
					'name'    => 'Boolean-based SQL injection',
					'pattern' => '/(\'|")\s*(or|and)\s*(\'|")?\s*\d+\s*(=|<|>)\s*\d+/i',
					'scope'   => array( 'query', 'body', 'cookie' ),
				),
				array(
					'id'      => 'TS-SQLI-1024',
					'name'    => 'Stacked query or table read',
					'pattern' => '/\b(select|insert|update|delete)\b[\s\S]{0,40}\bfrom\b[\s\S]{0,20}(information_schema|wp_users|wp_options|users)\b/i',
					'scope'   => array( 'query', 'body', 'cookie' ),
				),
			),
			'xss'       => array(
				array(
					'id'      => 'TS-XSS-2004',
					'name'    => 'Event-handler injection',
					'pattern' => '/<[^>]+\bon(load|error|click|mouseover|focus|toggle|animationstart)\s*=/i',
					'scope'   => array( 'query', 'body' ),
				),
				array(
					'id'      => 'TS-XSS-2011',
					'name'    => 'Injected code in comment',
					'pattern' => '/<\s*(script|iframe|object|embed|svg|math)\b/i',
					'scope'   => array( 'query', 'body' ),
				),
				array(
					'id'      => 'TS-XSS-2019',
					'name'    => 'Script URI in parameter',
					'pattern' => '/(javascript|vbscript|data)\s*:\s*[^\s]*(alert|eval|atob|fromCharCode|document\.cookie)/i',
					'scope'   => array( 'query', 'body' ),
				),
			),
			'auth'      => array(
				array(
					'id'      => 'TS-AUTH-3010',
					'name'    => 'Password-reset key tampering',
					'pattern' => '/[\x00-\x1f<>"\'\\\\]/',
					'scope'   => array( 'resetkey' ),
				),
			),
			'priv'      => array(
				array(
					'id'      => 'TS-PRIV-4002',
					'name'    => 'Unauthorised option update',
					'pattern' => '/\boption(_name)?(\[[^\]]*\])?\s*=\s*(default_role|users_can_register|siteurl|home|active_plugins)\b/i',
					'scope'   => array( 'query', 'body', 'pair' ),
				),
				array(
					'id'      => 'TS-PRIV-4007',
					'name'    => 'Role change by low-privilege user',
					'pattern' => '/\brole[s]?(\[[^\]]*\])?\s*=\s*(administrator|super[\s_-]*admin)\b/i',
					'scope'   => array( 'query', 'body', 'pair' ),
				),
			),
			'upload'    => array(
				array(
					'id'      => 'TS-UPL-6001',
					'name'    => 'Executable disguised as a document',
					'pattern' => '',
					'scope'   => array( 'upload' ),
				),
				array(
					'id'      => 'TS-UPL-6003',
					'name'    => 'Blocked file extension',
					'pattern' => '',
					'scope'   => array( 'upload' ),
				),
			),
			'malicious' => array(
				array(
					'id'      => 'TS-MAL-9004',
					'name'    => 'Sensitive file probe',
					'pattern' => '#/(\.env|\.git/|\.svn/|\.ssh/|wp-config\.php\.(bak|old|save|txt|swp)|wp-config\.bak|composer\.(json|lock)|package-lock\.json|\.DS_Store|debug\.log|error_log|backup\.(sql|zip|tar\.gz)|db\.sql)#i',
					'scope'   => array( 'path' ),
				),
				array(
					'id'      => 'TS-MAL-9012',
					'name'    => 'Known attack tool',
					'pattern' => '/(wpscan|sqlmap|nikto|acunetix|nessus|masscan|zgrab|dirbuster|gobuster|havij|nmap\s+scripting)/i',
					'scope'   => array( 'useragent' ),
				),
				array(
					'id'      => 'TS-MAL-9020',
					'name'    => 'Author enumeration',
					'pattern' => '/^\d{1,4}$/',
					'scope'   => array( 'author' ),
				),
			),
			'exploit'   => array(
				array(
					'id'      => 'TS-EXP-1102',
					'name'    => 'Path traversal',
					'pattern' => '#(\.\./|\.\.\\\\|%2e%2e[/%5c]|/etc/passwd|/proc/self/environ|c:\\\\windows)#i',
					'scope'   => array( 'path', 'query', 'body' ),
				),
				array(
					'id'      => 'TS-EXP-1120',
					'name'    => 'PHP object injection',
					'pattern' => '/(^|[;{])\s*O:\d+:"[a-z_\\\\][a-z0-9_\\\\]*":\d+:\{/i',
					'scope'   => array( 'query', 'body', 'cookie' ),
				),
				array(
					'id'      => 'TS-EXP-1131',
					'name'    => 'Remote code execution',
					'pattern' => '/\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|base64_decode|create_function)\s*\(\s*(\$|base64|chr|"|\')/i',
					'scope'   => array( 'query', 'body' ),
				),
				array(
					'id'      => 'TS-EXP-1140',
					'name'    => 'PHP wrapper in parameter',
					'pattern' => '#\b(php|data|expect|zip|phar|file)://#i',
					'scope'   => array( 'query', 'body' ),
				),
			),
		);
	}

	/**
	 * The translated name for a rule identifier.
	 *
	 * Rule names are stored untranslated so the firewall can run before
	 * `init`; the admin turns them back into the visitor's language here.
	 *
	 * @param string $rule_id  Rule identifier, e.g. TS-SQLI-1003.
	 * @param string $fallback Stored English name.
	 * @return string
	 */
	public static function rule_name( $rule_id, $fallback = '' ) {
		$names = array(
			'TS-SQLI-1003' => __( 'UNION-based SQL injection', 'teksecurity' ),
			'TS-SQLI-1011' => __( 'Time-based blind SQL injection', 'teksecurity' ),
			'TS-SQLI-1018' => __( 'Boolean-based SQL injection', 'teksecurity' ),
			'TS-SQLI-1024' => __( 'Stacked query or table read', 'teksecurity' ),
			'TS-XSS-2004'  => __( 'Event-handler injection', 'teksecurity' ),
			'TS-XSS-2011'  => __( 'Injected code in comment', 'teksecurity' ),
			'TS-XSS-2019'  => __( 'Script URI in parameter', 'teksecurity' ),
			// Retired signature: kept here so log rows written by an earlier
			// version still show a readable rule name.
			'TS-AUTH-3004' => __( 'REST request with forged nonce', 'teksecurity' ),
			'TS-AUTH-3010' => __( 'Password-reset key tampering', 'teksecurity' ),
			'TS-PRIV-4002' => __( 'Unauthorised option update', 'teksecurity' ),
			'TS-PRIV-4007' => __( 'Role change by low-privilege user', 'teksecurity' ),
			'TS-UPL-6001'  => __( 'Executable disguised as a document', 'teksecurity' ),
			'TS-UPL-6003'  => __( 'Blocked file extension', 'teksecurity' ),
			'TS-MAL-9004'  => __( 'Sensitive file probe', 'teksecurity' ),
			'TS-MAL-9012'  => __( 'Known attack tool', 'teksecurity' ),
			'TS-MAL-9020'  => __( 'Author enumeration', 'teksecurity' ),
			'TS-EXP-1102'  => __( 'Path traversal', 'teksecurity' ),
			'TS-EXP-1120'  => __( 'PHP object injection', 'teksecurity' ),
			'TS-EXP-1131'  => __( 'Remote code execution', 'teksecurity' ),
			'TS-EXP-1140'  => __( 'PHP wrapper in parameter', 'teksecurity' ),
			'TS-BF-7001'   => __( 'Login attempt limit exceeded', 'teksecurity' ),
			'TS-BF-7002'   => __( 'Login attempt with a blocked username', 'teksecurity' ),
			'TS-BF-7004'   => __( 'XML-RPC logins are turned off', 'teksecurity' ),
			'TS-IP-0001'   => __( 'Address is on your blocklist', 'teksecurity' ),
		);

		return isset( $names[ $rule_id ] ) ? $names[ $rule_id ] : $fallback;
	}

	/**
	 * Signature count for a module, shown as "N rules" in advanced view.
	 *
	 * @param string $module Module key.
	 * @return int
	 */
	public static function count( $module ) {
		$all = self::signatures();

		return isset( $all[ $module ] ) ? count( $all[ $module ] ) : 0;
	}
}
