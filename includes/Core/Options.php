<?php
/**
 * Settings storage.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Core;

use TekSecurity\Helpers\Endpoint;

defined( 'ABSPATH' ) || exit;

/**
 * Typed accessor around a single wp_option holding every plugin setting.
 */
class Options {

	const OPTION = 'teksecurity_settings';

	/**
	 * Runtime cache.
	 *
	 * @var array|null
	 */
	protected static $cache = null;

	/**
	 * Default settings. Mirrors the shape the React admin expects.
	 *
	 * @return array
	 */
	public static function defaults() {
		$base = array(
			'on'  => true,
			'act' => 'block',
		);

		return array(
			'onboarded'   => false,
			'mode'        => 'simple',
			'firewall'    => array(
				'mode'    => 'protect',
				'modules' => array(
					'malicious' => $base,
					'exploit'   => $base,
					'sqli'      => $base,
					'xss'       => $base,
					'auth'      => $base,
					'priv'      => $base,
					'plugin'    => array( 'on' => true ),
					'upload'    => array( 'on' => true ),
					'brute'     => array( 'on' => true ),
					'rate'      => array( 'on' => true ),
				),
			),
			'login'       => array(
				'attempts'    => 5,
				'lockout'     => '30',
				'window'      => '15',
				'block_admin' => true,
				'xmlrpc'      => true,
			),
			'twofactor'   => array(
				'on'       => true,
				'methods'  => array(
					'app'    => true,
					'email'  => true,
					'backup' => true,
				),
				'grace'    => '7',
				'remember' => '30',
			),
			'ratelimit'   => array(
				'preset' => 'balanced',
				'act'    => 'throttle',
				'bypass' => true,
				'rules'  => array(),
			),
			'uploads'     => array(
				'exts'   => array( 'php', 'phtml', 'phar', 'php5', 'php7', 'pht', 'exe', 'sh', 'cgi', 'htaccess' ),
				'scan'   => true,
				'svg'    => true,
				'guests' => true,
			),
			'integrity'   => array(
				'on'       => true,
				'schedule' => 'daily',
			),
			'vulnerability' => array(
				'on'       => true,
				'schedule' => 'twicedaily',
				'shields'  => array(),
			),
			'alerts'      => array(
				'email'  => '',
				'alerts' => 'critical',
				'weekly' => true,
			),
			'data'        => array(
				'retention' => '30',
				'proxy'     => 'direct',
			),
		);
	}

	/**
	 * Get every setting, merged over defaults.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored = get_option( self::OPTION, array() );
			$stored = is_array( $stored ) ? $stored : array();

			self::$cache = self::merge( self::defaults(), $stored );

			if ( '' === self::$cache['alerts']['email'] ) {
				self::$cache['alerts']['email'] = get_option( 'admin_email' );
			}
			if ( empty( self::$cache['ratelimit']['rules'] ) ) {
				self::$cache['ratelimit']['rules'] = self::preset_rules( self::$cache['ratelimit']['preset'] );
			}

			self::$cache['ratelimit']['rules'] = self::relocate_rules( self::$cache['ratelimit']['rules'] );
		}

		return self::$cache;
	}

	/**
	 * Read a dotted path, e.g. `login.attempts`.
	 *
	 * @param string $path    Dotted key path.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public static function get( $path, $default = null ) {
		$value = self::all();

		foreach ( explode( '.', $path ) as $segment ) {
			if ( ! is_array( $value ) || ! array_key_exists( $segment, $value ) ) {
				return $default;
			}
			$value = $value[ $segment ];
		}

		return $value;
	}

	/**
	 * Write a dotted path.
	 *
	 * @param string $path  Dotted key path.
	 * @param mixed  $value New value.
	 * @return void
	 */
	public static function set( $path, $value ) {
		$all      = self::all();
		$segments = explode( '.', $path );
		$cursor   = &$all;

		foreach ( $segments as $i => $segment ) {
			if ( count( $segments ) - 1 === $i ) {
				$cursor[ $segment ] = $value;
				break;
			}
			if ( ! isset( $cursor[ $segment ] ) || ! is_array( $cursor[ $segment ] ) ) {
				$cursor[ $segment ] = array();
			}
			$cursor = &$cursor[ $segment ];
		}
		unset( $cursor );

		self::save( $all );
	}

	/**
	 * Replace the whole settings array.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	public static function save( array $settings ) {
		self::$cache = self::merge( self::defaults(), $settings );
		update_option( self::OPTION, self::$cache, false );
	}

	/**
	 * Forget the runtime cache.
	 *
	 * @return void
	 */
	public static function flush() {
		self::$cache = null;
	}

	/**
	 * Rate-limit rules for a strictness preset.
	 *
	 * @param string $preset relaxed|balanced|strict|custom.
	 * @return array
	 */
	public static function preset_rules( $preset ) {
		$factors = array(
			'relaxed'  => 2,
			'balanced' => 1,
			'strict'   => 0.5,
		);
		$factor  = isset( $factors[ $preset ] ) ? $factors[ $preset ] : 1;

		// Names are stored untranslated: this runs before `init`, and the admin
		// translates them for display through self::rule_label().
		$base = array(
			array( 'site', 'All requests', '/*', 240 ),
			array( 'login', 'Login page', Endpoint::login_path(), 10 ),
			array( 'rest', 'REST API', Endpoint::rest_path() . '*', 120 ),
			array( 'ajax', 'Admin AJAX', Endpoint::admin_ajax_path(), 180 ),
			array( 'search', 'Site search', '/?s=*', 30 ),
			array( 'xmlrpc', 'XML-RPC', Endpoint::xmlrpc_path(), 0 ),
		);

		$rules = array();
		foreach ( $base as $row ) {
			list( $key, $name, $path, $limit ) = $row;
			$rules[] = array(
				'key'   => $key,
				'name'  => $name,
				'path'  => $path,
				'limit' => $limit ? max( 1, (int) round( $limit * $factor ) ) : 0,
				'on'    => true,
			);
		}

		return $rules;
	}

	/**
	 * Point the built-in rules at wherever their endpoint actually lives.
	 *
	 * A rule's path is stored, so a site that moved WordPress, renamed
	 * `wp-admin/` or changed its REST prefix after the rules were first
	 * written - or one upgrading from a release that wrote the stock paths
	 * literally - would be left matching paths no request carries.
	 *
	 * Only a path still holding its stock value is moved. A path the owner has
	 * edited is theirs, and is left exactly as they set it.
	 *
	 * @param array $rules Stored rate-limit rules.
	 * @return array
	 */
	protected static function relocate_rules( $rules ) {
		$stock = array(
			'login'  => array( '/wp-login.php', Endpoint::login_path() ),
			'rest'   => array( '/wp-json/*', Endpoint::rest_path() . '*' ),
			// No stock path is kept for this one: it is recognised by its file
			// name, so an earlier release's stored path is found without this
			// class repeating it.
			'ajax'   => array( null, Endpoint::admin_ajax_path() ),
			'xmlrpc' => array( '/xmlrpc.php', Endpoint::xmlrpc_path() ),
		);

		foreach ( (array) $rules as $i => $rule ) {
			if ( ! is_array( $rule ) || ! isset( $rule['key'], $rule['path'] ) ) {
				continue;
			}

			if ( ! isset( $stock[ $rule['key'] ] ) ) {
				continue;
			}

			list( $was, $now ) = $stock[ $rule['key'] ];

			if ( null === $was ) {
				$is_stock = '' !== $now && wp_basename( $now ) === wp_basename( $rule['path'] );
			} else {
				$is_stock = $was === $rule['path'];
			}

			if ( $is_stock ) {
				$rules[ $i ]['path'] = $now;
			}
		}

		return $rules;
	}

	/**
	 * The translated label for a rate-limit rule.
	 *
	 * @param string $key      Rule key.
	 * @param string $fallback Stored English name.
	 * @return string
	 */
	public static function rule_label( $key, $fallback = '' ) {
		$labels = array(
			'site'   => __( 'All requests', 'teksecurity' ),
			'login'  => __( 'Login page', 'teksecurity' ),
			'rest'   => __( 'REST API', 'teksecurity' ),
			'ajax'   => __( 'Admin AJAX', 'teksecurity' ),
			'search' => __( 'Site search', 'teksecurity' ),
			'xmlrpc' => __( 'XML-RPC', 'teksecurity' ),
		);

		return isset( $labels[ $key ] ) ? $labels[ $key ] : $fallback;
	}

	/**
	 * Recursive array merge that keeps list values intact.
	 *
	 * @param array $defaults Defaults.
	 * @param array $values   Stored values.
	 * @return array
	 */
	protected static function merge( array $defaults, array $values ) {
		foreach ( $values as $key => $value ) {
			if ( isset( $defaults[ $key ] ) && is_array( $defaults[ $key ] ) && is_array( $value ) && ! self::is_list( $defaults[ $key ] ) ) {
				$defaults[ $key ] = self::merge( $defaults[ $key ], $value );
			} else {
				$defaults[ $key ] = $value;
			}
		}

		return $defaults;
	}

	/**
	 * Whether an array is a plain list.
	 *
	 * @param array $array Array.
	 * @return bool
	 */
	protected static function is_list( array $array ) {
		return array_keys( $array ) === range( 0, count( $array ) - 1 );
	}
}
