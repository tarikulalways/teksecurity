<?php
/**
 * Upload filtering, rate limiting and general WordPress hardening.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Modules;

use TekSecurity\Core\Options;
use TekSecurity\Core\Plugin;
use TekSecurity\Helpers\Ip;
use TekSecurity\Helpers\IpList;
use TekSecurity\Helpers\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * The protections that do not need a signature match.
 */
class Hardening {

	const RATE_PREFIX = 'teksec_rl_';

	/**
	 * Hook in.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'plugins_loaded', array( $this, 'rate_limit' ), 2 );

		add_filter( 'wp_handle_upload_prefilter', array( $this, 'filter_upload' ) );
		add_filter( 'wp_handle_sideload_prefilter', array( $this, 'filter_upload' ) );

		add_filter( 'upload_mimes', array( $this, 'filter_mimes' ) );
		add_filter( 'wp_check_filetype_and_ext', array( $this, 'check_filetype' ), 10, 4 );

		add_action( 'init', array( $this, 'apply_hardening' ) );
	}

	/* --------------------------------------------------------------------- *
	 * Rate limiting
	 * --------------------------------------------------------------------- */

	/**
	 * Count this request against the matching rule and act when it overflows.
	 *
	 * @return void
	 */
	public function rate_limit() {
		if ( ! Options::get( 'firewall.modules.rate.on', true ) ) {
			return;
		}

		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$ip = Ip::current();

		if ( IpList::is_allowed( $ip ) ) {
			return;
		}

		if ( Options::get( 'ratelimit.bypass', true ) && current_user_can( 'manage_options' ) ) {
			return;
		}

		$rule = $this->matching_rule( Firewall::uri() );

		if ( ! $rule ) {
			return;
		}

		if ( 0 === (int) $rule['limit'] ) {
			$this->rate_deny( $rule, 0, $ip );
			return;
		}

		$key   = self::RATE_PREFIX . $rule['key'] . '_' . md5( $ip );
		$count = (int) get_transient( $key ) + 1;

		set_transient( $key, $count, MINUTE_IN_SECONDS );

		if ( $count > (int) $rule['limit'] ) {
			$this->rate_deny( $rule, $count, $ip );
		}
	}

	/**
	 * The most specific enabled rule for a URI.
	 *
	 * @param string $uri Request URI.
	 * @return array|null
	 */
	protected function matching_rule( $uri ) {
		$rules = (array) Options::get( 'ratelimit.rules', array() );
		$path  = strtok( $uri, '?' );
		$match = null;

		foreach ( $rules as $rule ) {
			if ( empty( $rule['on'] ) ) {
				continue;
			}

			$pattern = $rule['path'];
			$hit     = false;

			if ( '/*' === $pattern ) {
				$hit = true;
			} elseif ( '/?s=*' === $pattern ) {
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$hit = isset( $_GET['s'] );
			} elseif ( false !== strpos( $pattern, '*' ) ) {
				$hit = 0 === strpos( $path, rtrim( $pattern, '*' ) );
			} else {
				$hit = $path === $pattern;
			}

			if ( ! $hit ) {
				continue;
			}

			// Prefer the narrower rule: a longer pattern wins over "/*".
			if ( null === $match || strlen( $pattern ) > strlen( $match['path'] ) ) {
				$match = $rule;
			}
		}

		return $match;
	}

	/**
	 * Throttle or block a request that went over its limit.
	 *
	 * @param array  $rule  The rule that matched.
	 * @param int    $count Requests counted in this minute.
	 * @param string $ip    Visitor address.
	 * @return void
	 */
	protected function rate_deny( array $rule, $count, $ip ) {
		$block = 'block' === Options::get( 'ratelimit.act', 'throttle' );

		Logger::record(
			array(
				'attack_type' => 'rate',
				'rule_id'     => 'TS-RL-' . strtoupper( substr( $rule['key'], 0, 8 ) ),
				'rule_name'   => sprintf( '%s rate limit', $rule['name'] ),
				'action'      => 'blocked',
				'method'      => Firewall::method(),
				'path'        => Firewall::uri(),
				'matched_in'  => $rule['path'],
				'payload'     => $count
					? sprintf( '%1$d requests in 60 s (limit %2$d)', $count, (int) $rule['limit'] )
					: 'This path is blocked completely',
				'ip'          => $ip,
			)
		);

		if ( ! headers_sent() ) {
			status_header( $block ? 403 : 429 );
			nocache_headers();
			header( 'Retry-After: ' . ( $block ? 600 : 60 ) );
			header( 'X-TekSecurity: rate-limited' );
		}

		wp_die(
			esc_html( Plugin::early_text( 'Too many requests from your address. Please wait a moment and try again.', 'rate_limit_message' ) ),
			esc_html( Plugin::early_text( 'Slow down', 'rate_limit_title' ) ),
			array( 'response' => $block ? 403 : 429 )
		);
	}

	/* --------------------------------------------------------------------- *
	 * Uploads
	 * --------------------------------------------------------------------- */

	/**
	 * Reject uploads with a blocked extension or executable content.
	 *
	 * @param array $file Entry from $_FILES.
	 * @return array
	 */
	public function filter_upload( $file ) {
		if ( ! Options::get( 'firewall.modules.upload.on', true ) ) {
			return $file;
		}

		if ( ! empty( $file['error'] ) ) {
			return $file;
		}

		if ( ! is_user_logged_in() && ! Options::get( 'uploads.guests', true ) ) {
			return $file;
		}

		$name    = isset( $file['name'] ) ? (string) $file['name'] : '';
		$blocked = array_map( 'strtolower', (array) Options::get( 'uploads.exts', array() ) );

		// Every dotted segment counts, so invoice.pdf.php is caught too.
		$segments = array_slice( explode( '.', strtolower( $name ) ), 1 );

		foreach ( $segments as $segment ) {
			if ( in_array( $segment, $blocked, true ) ) {
				return $this->reject_upload(
					$file,
					'TS-UPL-6003',
					'Blocked file extension',
					sprintf( '%s · .%s', $name, $segment ),
					sprintf(
						/* translators: %s: file extension, e.g. "php". */
						__( 'Files ending in .%s are blocked because they can run code on the server.', 'teksecurity' ),
						$segment
					)
				);
			}
		}

		$path = isset( $file['tmp_name'] ) ? $file['tmp_name'] : '';

		if ( Options::get( 'uploads.scan', true ) && $path && is_readable( $path ) ) {
			$head = (string) file_get_contents( $path, false, null, 0, 8192 ); // phpcs:ignore WordPress.WP.AlternativeFunctions

			if ( preg_match( '/<\?php|<\?=|<%|#!\s*\/(bin|usr)\//i', $head ) ) {
				return $this->reject_upload(
					$file,
					'TS-UPL-6001',
					'Executable disguised as a document',
					sprintf( '%s · %s · %s', $name, size_format( (int) ( $file['size'] ?? 0 ) ), 'contains PHP code' ),
					__( 'This file contains code that could run on your server, so it was not saved.', 'teksecurity' )
				);
			}
		}

		if ( Options::get( 'uploads.svg', true ) && preg_match( '/\.svg$/i', $name ) && $path && is_readable( $path ) ) {
			$this->clean_svg( $path );
		}

		return $file;
	}

	/**
	 * Log the rejection and hand WordPress an error.
	 *
	 * @param array  $file    Upload entry.
	 * @param string $rule_id Rule identifier.
	 * @param string $rule    Rule name.
	 * @param string $payload What was seen.
	 * @param string $message Message shown to the uploader.
	 * @return array
	 */
	protected function reject_upload( array $file, $rule_id, $rule, $payload, $message ) {
		Logger::record(
			array(
				'attack_type' => 'upload',
				'rule_id'     => $rule_id,
				'rule_name'   => $rule,
				'action'      => 'blocked',
				'method'      => Firewall::method(),
				'path'        => Firewall::uri(),
				'matched_in'  => sprintf( '%s (file)', isset( $file['name'] ) ? $file['name'] : 'upload' ),
				'payload'     => $payload,
			)
		);

		$file['error'] = $message;

		return $file;
	}

	/**
	 * Strip scripts and event handlers out of an SVG before it is stored.
	 *
	 * @param string $path Temporary file path.
	 * @return void
	 */
	protected function clean_svg( $path ) {
		$svg = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( '' === $svg ) {
			return;
		}

		$clean = preg_replace(
			array(
				'#<script[\s\S]*?</script>#i',
				'#<!ENTITY[\s\S]*?>#i',
				'#\son[a-z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)#i',
				'#(href|xlink:href)\s*=\s*("|\')\s*(javascript|data)\s*:[^"\']*\2#i',
			),
			'',
			$svg
		);

		if ( null !== $clean && $clean !== $svg ) {
			file_put_contents( $path, $clean ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	/**
	 * Drop blocked extensions out of the allowed mime map.
	 *
	 * @param array $mimes Allowed types.
	 * @return array
	 */
	public function filter_mimes( $mimes ) {
		if ( ! Options::get( 'firewall.modules.upload.on', true ) ) {
			return $mimes;
		}

		$blocked = array_map( 'strtolower', (array) Options::get( 'uploads.exts', array() ) );

		foreach ( array_keys( $mimes ) as $pattern ) {
			foreach ( explode( '|', (string) $pattern ) as $ext ) {
				if ( in_array( $ext, $blocked, true ) ) {
					unset( $mimes[ $pattern ] );
					break;
				}
			}
		}

		return $mimes;
	}

	/**
	 * Refuse files whose real type does not match the extension.
	 *
	 * @param array  $data     Checked type data.
	 * @param string $file     Full path.
	 * @param string $filename Name.
	 * @param array  $mimes    Allowed types.
	 * @return array
	 */
	public function check_filetype( $data, $file, $filename, $mimes ) {
		unset( $file, $mimes );

		if ( ! Options::get( 'firewall.modules.upload.on', true ) ) {
			return $data;
		}

		$blocked = array_map( 'strtolower', (array) Options::get( 'uploads.exts', array() ) );

		foreach ( array_slice( explode( '.', strtolower( (string) $filename ) ), 1 ) as $segment ) {
			if ( in_array( $segment, $blocked, true ) ) {
				return array(
					'ext'             => false,
					'type'            => false,
					'proper_filename' => false,
				);
			}
		}

		return $data;
	}

	/* --------------------------------------------------------------------- *
	 * General hardening
	 * --------------------------------------------------------------------- */

	/**
	 * Small measures that cost nothing and remove easy targets.
	 *
	 * @return void
	 */
	public function apply_hardening() {
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );

		if ( Options::get( 'firewall.modules.priv.on', true ) ) {
			add_filter( 'rest_endpoints', array( $this, 'restrict_user_endpoints' ) );
		}

		if ( Options::get( 'firewall.modules.malicious.on', true ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_enumeration' ), 1 );
		}
	}

	/**
	 * Require a login to list users over the REST API.
	 *
	 * @param array $endpoints REST endpoints.
	 * @return array
	 */
	public function restrict_user_endpoints( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		foreach ( array( '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ) as $route ) {
			if ( isset( $endpoints[ $route ] ) ) {
				unset( $endpoints[ $route ] );
			}
		}

		return $endpoints;
	}

	/**
	 * Stop ?author=N from revealing usernames.
	 *
	 * @return void
	 */
	public function block_author_enumeration() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( is_admin() || is_user_logged_in() || ! isset( $_GET['author'] ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$author = sanitize_text_field( wp_unslash( $_GET['author'] ) );

		if ( ! is_numeric( $author ) ) {
			return;
		}

		Logger::record(
			array(
				'attack_type' => 'malicious',
				'rule_id'     => 'TS-MAL-9020',
				'rule_name'   => 'Author enumeration',
				'action'      => 'blocked',
				'method'      => Firewall::method(),
				'path'        => Firewall::uri(),
				'matched_in'  => 'author (query)',
				'payload'     => 'author=' . $author,
			)
		);

		wp_safe_redirect( home_url( '/' ), 302 );
		exit;
	}
}
