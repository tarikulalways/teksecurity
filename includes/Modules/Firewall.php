<?php
/**
 * Web application firewall.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Modules;

use TekSecurity\Core\Installer;
use TekSecurity\Core\Options;
use TekSecurity\Core\Plugin;
use TekSecurity\Helpers\Ip;
use TekSecurity\Helpers\IpList;
use TekSecurity\Helpers\Logger;
use TekSecurity\Helpers\Rules;

defined( 'ABSPATH' ) || exit;

/**
 * Inspects each request before WordPress finishes loading.
 */
class Firewall {

	/**
	 * Rule exclusions, loaded once.
	 *
	 * @var array|null
	 */
	protected static $exclusions = null;

	/**
	 * Hook into the request lifecycle.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'plugins_loaded', array( $this, 'inspect' ), 1 );
	}

	/**
	 * Run the firewall against the current request.
	 *
	 * @return void
	 */
	public function inspect() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		/**
		 * Short-circuit the firewall for a request.
		 *
		 * @param bool $skip Whether to skip inspection.
		 */
		if ( apply_filters( 'teksecurity_skip_firewall', false ) ) {
			return;
		}

		$ip = Ip::current();

		if ( IpList::is_allowed( $ip ) ) {
			return;
		}

		if ( IpList::is_blocked( $ip ) ) {
			Logger::record(
				array(
					'attack_type' => 'malicious',
					'rule_id'     => 'TS-IP-0001',
					'rule_name'   => 'Address is on your blocklist',
					'action'      => 'blocked',
					'method'      => self::method(),
					'path'        => self::uri(),
					'matched_in'  => 'ip',
					'payload'     => $ip,
				)
			);
			$this->deny();
		}

		if ( 'off' === Options::get( 'firewall.mode', 'protect' ) ) {
			return;
		}

		$hit = $this->match();

		if ( ! $hit ) {
			return;
		}

		$mode   = Options::get( 'firewall.mode', 'protect' );
		$module = Options::get( 'firewall.modules.' . $hit['type'], array() );
		$action = 'learning' === $mode || 'log' === ( $module['act'] ?? 'block' ) ? 'logged' : 'blocked';

		Logger::record(
			array(
				'attack_type' => $hit['type'],
				'rule_id'     => $hit['rule_id'],
				'rule_name'   => $hit['rule_name'],
				'action'      => $action,
				'method'      => self::method(),
				'path'        => self::uri(),
				'matched_in'  => $hit['matched_in'],
				'payload'     => $hit['payload'],
			)
		);

		if ( 'blocked' === $action ) {
			$this->deny();
		}
	}

	/**
	 * Find the first signature that matches the request.
	 *
	 * @return array|null
	 */
	protected function match() {
		$candidates = $this->candidates();
		$signatures = Rules::signatures();
		$path       = strtok( self::uri(), '?' );

		foreach ( $signatures as $module => $rules ) {
			$settings = Options::get( 'firewall.modules.' . $module, array( 'on' => true ) );

			if ( empty( $settings['on'] ) ) {
				continue;
			}

			foreach ( $rules as $rule ) {
				if ( '' === $rule['pattern'] ) {
					continue; // Upload rules run inside the Hardening module.
				}

				if ( $this->is_excluded( $rule['id'], $path ) ) {
					continue;
				}

				foreach ( $rule['scope'] as $scope ) {
					if ( empty( $candidates[ $scope ] ) ) {
						continue;
					}

					foreach ( $candidates[ $scope ] as $where => $value ) {
						if ( ! is_string( $value ) || '' === $value ) {
							continue;
						}

						if ( preg_match( $rule['pattern'], $value ) ) {
							return array(
								'type'       => $module,
								'rule_id'    => $rule['id'],
								'rule_name'  => $rule['name'],
								'matched_in' => $where,
								'payload'    => substr( $value, 0, 500 ),
							);
						}
					}
				}
			}
		}

		return null;
	}

	/**
	 * Flatten the request into the scopes the signatures test.
	 *
	 * @return array
	 */
	protected function candidates() {
		$uri   = self::uri();
		$query = array();
		$body  = array();

		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
		foreach ( (array) $_GET as $key => $value ) {
			$this->flatten( $query, sanitize_key( (string) $key ) . ' (query)', $value );
		}
		foreach ( (array) $_POST as $key => $value ) {
			$this->flatten( $body, sanitize_key( (string) $key ) . ' (body)', $value );
		}
		// phpcs:enable

		$cookies = array();
		foreach ( (array) $_COOKIE as $key => $value ) {
			if ( 0 === strpos( (string) $key, 'wordpress_' ) || 0 === strpos( (string) $key, 'wp-settings' ) ) {
				continue;
			}
			$this->flatten( $cookies, sanitize_key( (string) $key ) . ' (cookie)', $value );
		}

		// Some rules only make sense against the parameter name and its value
		// together, e.g. "roles[]=administrator".
		$pairs = array();
		foreach ( array_merge( $query, $body ) as $label => $value ) {
			$name           = trim( (string) strtok( (string) $label, ' ' ) );
			$pairs[ $label ] = $name . '=' . $value;
		}

		$candidates = array(
			'path'   => array( 'path' => rawurldecode( $uri ) ),
			'query'  => $query,
			'body'   => $body,
			'cookie' => $cookies,
			'pair'   => $pairs,
		);

		$agent = Ip::user_agent();
		if ( '' !== $agent ) {
			$candidates['useragent'] = array( 'User-Agent (header)' => $agent );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['author'] ) && ! is_user_logged_in() ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$candidates['author'] = array( 'author (query)' => sanitize_text_field( wp_unslash( $_GET['author'] ) ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['key'] ) && false !== strpos( $uri, 'action=rp' ) ) {
			// Unslashed and bounded inside self::raw(); see that method.
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			$candidates['resetkey'] = array( 'key (query)' => self::raw( $_GET['key'] ) );
		}

		/**
		 * Filter the request values the firewall inspects.
		 *
		 * @param array $candidates Scope => [ label => value ].
		 */
		return apply_filters( 'teksecurity_firewall_candidates', $candidates );
	}

	/**
	 * Flatten nested request data into label => string pairs.
	 *
	 * @param array  $out   Accumulator, by reference.
	 * @param string $label Label for this value.
	 * @param mixed  $value Value.
	 * @param int    $depth Recursion guard.
	 * @return void
	 */
	protected function flatten( array &$out, $label, $value, $depth = 0 ) {
		if ( $depth > 4 ) {
			return;
		}

		if ( is_array( $value ) ) {
			foreach ( $value as $key => $item ) {
				$this->flatten( $out, $label . '[' . sanitize_key( (string) $key ) . ']', $item, $depth + 1 );
			}
			return;
		}

		if ( is_scalar( $value ) ) {
			$out[ $label ] = rawurldecode( self::raw( $value ) );
		}
	}

	/**
	 * Whether a rule is excluded on a path.
	 *
	 * @param string $rule_id Rule identifier.
	 * @param string $path    Request path without the query string.
	 * @return bool
	 */
	protected function is_excluded( $rule_id, $path ) {
		foreach ( self::exclusions() as $row ) {
			if ( $row['ruleId'] === $rule_id && $row['path'] === $path ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Every rule exclusion.
	 *
	 * @return array
	 */
	public static function exclusions() {
		global $wpdb;

		if ( null === self::$exclusions ) {
			$table = esc_sql( Installer::table( 'exclusions' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
			$rows = $wpdb->get_results( "SELECT id, rule_id, path, created_at FROM {$table} ORDER BY created_at DESC, id DESC", ARRAY_A );

			self::$exclusions = array_map(
				static function ( $row ) {
					return array(
						'id'        => (int) $row['id'],
						'ruleId'    => $row['rule_id'],
						'path'      => $row['path'],
						'createdAt' => $row['created_at'],
					);
				},
				(array) $rows
			);
		}

		return self::$exclusions;
	}

	/**
	 * Add a rule exclusion.
	 *
	 * @param string $rule_id Rule identifier.
	 * @param string $path    Path the rule should skip.
	 * @return array
	 */
	public static function add_exclusion( $rule_id, $path ) {
		global $wpdb;

		$rule_id = substr( sanitize_text_field( $rule_id ), 0, 40 );
		$path    = substr( esc_url_raw( $path ), 0, 190 );

		$table = esc_sql( Installer::table( 'exclusions' ) );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$table} (rule_id, path, created_at) VALUES (%s, %s, %s)",
				$rule_id,
				$path,
				current_time( 'mysql' )
			)
		);
		// phpcs:enable

		self::$exclusions = null;

		return array(
			'id'        => (int) $wpdb->insert_id,
			'ruleId'    => $rule_id,
			'path'      => $path,
			'createdAt' => current_time( 'mysql' ),
		);
	}

	/**
	 * Remove a rule exclusion.
	 *
	 * @param int $id Row id.
	 * @return bool
	 */
	public static function remove_exclusion( $id ) {
		global $wpdb;

		self::$exclusions = null;

		return (bool) $wpdb->delete( Installer::table( 'exclusions' ), array( 'id' => (int) $id ), array( '%d' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Send a 403 and stop.
	 *
	 * @return void
	 */
	protected function deny() {
		/**
		 * Fires just before the firewall ends a blocked request.
		 */
		do_action( 'teksecurity_request_blocked' );

		if ( ! headers_sent() ) {
			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'X-TekSecurity: blocked' );
		}

		wp_die(
			esc_html( Plugin::early_text( 'This request was blocked by the site firewall. If you think this is a mistake, contact the site owner.', 'block_message' ) ),
			esc_html( Plugin::early_text( 'Request blocked', 'block_title' ) ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Request method.
	 *
	 * @return string
	 */
	public static function method() {
		return isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
	}

	/**
	 * Request URI.
	 *
	 * @return string
	 */
	public static function uri() {
		// Unslashed and bounded inside self::raw(); see that method.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		return isset( $_SERVER['REQUEST_URI'] ) ? self::raw( $_SERVER['REQUEST_URI'] ) : '/';
	}

	/**
	 * Read a request value the firewall has to inspect byte for byte.
	 *
	 * The signatures look for exactly the characters a sanitiser would remove —
	 * angle brackets, quotes, control characters, path traversal — so the value
	 * cannot be sanitised before it is matched or the rules would never fire.
	 * Instead it is unslashed, cut to a safe length and stripped of null bytes
	 * here, is only ever used as the subject of `preg_match()`, and is
	 * sanitised again by `Logger::record()` before anything is stored or by
	 * `esc_html()` before anything is printed.
	 *
	 * @param mixed $value Raw request value.
	 * @return string
	 */
	protected static function raw( $value ) {
		if ( ! is_scalar( $value ) ) {
			return '';
		}

		$value = str_replace( "\0", '', (string) wp_unslash( $value ) );

		return substr( $value, 0, 2000 );
	}
}
