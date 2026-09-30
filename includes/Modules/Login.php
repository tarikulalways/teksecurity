<?php
/**
 * Brute-force protection for wp-login.php and XML-RPC.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Modules;

use TekSecurity\Core\Installer;
use TekSecurity\Core\Options;
use TekSecurity\Helpers\Ip;
use TekSecurity\Helpers\IpList;
use TekSecurity\Helpers\Logger;
use WP_Error;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Counts failed logins per IP and locks the IP out past the threshold.
 */
class Login {

	const ATTEMPT_PREFIX = 'teksec_login_';

	/**
	 * Hook in.
	 *
	 * @return void
	 */
	public function register() {
		add_filter( 'authenticate', array( $this, 'pre_authenticate' ), 30, 3 );
		add_action( 'wp_login_failed', array( $this, 'on_failed' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'on_success' ), 10, 2 );
		add_filter( 'xmlrpc_enabled', array( $this, 'filter_xmlrpc' ) );
		add_filter( 'login_errors', array( $this, 'generic_error' ) );
	}

	/**
	 * Whether the module is switched on.
	 *
	 * @return bool
	 */
	protected function enabled() {
		return (bool) Options::get( 'firewall.modules.brute.on', true );
	}

	/**
	 * Refuse the login attempt while the IP is locked out.
	 *
	 * @param null|WP_User|WP_Error $user     Current result.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return null|WP_User|WP_Error
	 */
	public function pre_authenticate( $user, $username, $password ) {
		unset( $password );

		if ( ! $this->enabled() || '' === $username ) {
			return $user;
		}

		$ip = Ip::current();

		if ( IpList::is_allowed( $ip ) ) {
			return $user;
		}

		$lock = self::find_lock( $ip );

		if ( $lock ) {
			return new WP_Error(
				'teksecurity_locked_out',
				sprintf(
					/* translators: %s: human readable time difference, e.g. "28 minutes". */
					__( '<strong>Too many failed attempts.</strong> This address is locked out for another %s.', 'teksecurity' ),
					human_time_diff( time(), strtotime( $lock['expiresAt'] ) )
				)
			);
		}

		if ( Options::get( 'login.block_admin', true ) && in_array( strtolower( $username ), array( 'admin', 'administrator' ), true ) && ! username_exists( $username ) ) {
			$this->lock_out( $ip, $username, (int) Options::get( 'login.attempts', 5 ) );

			Logger::record(
				array(
					'attack_type' => 'brute',
					'rule_id'     => 'TS-BF-7002',
					'rule_name'   => 'Login attempt with a blocked username',
					'action'      => 'blocked',
					'method'      => Firewall::method(),
					'path'        => Firewall::uri(),
					'matched_in'  => 'log (body)',
					'payload'     => 'log=' . $username,
				)
			);

			return new WP_Error(
				'teksecurity_blocked_username',
				__( '<strong>Blocked.</strong> That username is not allowed to sign in from this address.', 'teksecurity' )
			);
		}

		return $user;
	}

	/**
	 * Count a failed login and lock the IP out when the threshold is crossed.
	 *
	 * @param string        $username Submitted username.
	 * @param WP_Error|null $error    Authentication error.
	 * @return void
	 */
	public function on_failed( $username, $error = null ) {
		if ( ! $this->enabled() ) {
			return;
		}

		$code = is_wp_error( $error ) ? $error->get_error_code() : '';
		// A user being sent to the second step has not failed anything yet, and
		// wrong codes are counted by TwoFactor::register_failure() instead.
		$not_a_failure = array(
			'teksecurity_locked_out',
			'teksecurity_blocked_username',
			'teksecurity_2fa_required',
		);

		if ( in_array( $code, $not_a_failure, true ) ) {
			return;
		}

		$ip = Ip::current();

		if ( IpList::is_allowed( $ip ) ) {
			return;
		}

		$window   = max( 1, (int) Options::get( 'login.window', 15 ) );
		$max      = max( 2, (int) Options::get( 'login.attempts', 5 ) );
		$key      = self::ATTEMPT_PREFIX . md5( $ip );
		$attempts = (int) get_transient( $key ) + 1;

		set_transient( $key, $attempts, $window * MINUTE_IN_SECONDS );

		if ( $attempts < $max ) {
			return;
		}

		delete_transient( $key );
		$this->lock_out( $ip, $username, $attempts );

		Logger::record(
			array(
				'attack_type' => 'brute',
				'rule_id'     => 'TS-BF-7001',
				'rule_name'   => 'Login attempt limit exceeded',
				'action'      => 'blocked',
				'method'      => Firewall::method(),
				'path'        => Firewall::uri(),
				'matched_in'  => 'log (body)',
				'payload'     => sprintf(
					'log=%1$s · %2$d failed attempts in %3$d min',
					$username,
					$attempts,
					$window
				),
			)
		);

		/**
		 * Fires when an IP is locked out for repeated failed logins.
		 *
		 * @param string $ip       Locked address.
		 * @param string $username Last username tried.
		 * @param int    $attempts Failed attempts counted.
		 */
		do_action( 'teksecurity_ip_locked_out', $ip, $username, $attempts );
	}

	/**
	 * Clear the counter after a successful login.
	 *
	 * @param string  $username Username.
	 * @param WP_User $user     User object.
	 * @return void
	 */
	public function on_success( $username, $user = null ) {
		unset( $username, $user );

		delete_transient( self::ATTEMPT_PREFIX . md5( Ip::current() ) );
	}

	/**
	 * Turn XML-RPC off when the setting asks for it.
	 *
	 * @param bool $enabled Current value.
	 * @return bool
	 */
	public function filter_xmlrpc( $enabled ) {
		if ( ! $this->enabled() || ! Options::get( 'login.xmlrpc', true ) ) {
			return $enabled;
		}

		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return $enabled;
		}

		Logger::record(
			array(
				'attack_type' => 'brute',
				'rule_id'     => 'TS-BF-7004',
				'rule_name'   => 'XML-RPC logins are turned off',
				'action'      => 'blocked',
				'method'      => Firewall::method(),
				'path'        => Firewall::uri(),
				'matched_in'  => 'xmlrpc.php',
				'payload'     => 'XML-RPC authentication request',
			)
		);

		return false;
	}

	/**
	 * Never tell an attacker which half of the credentials was wrong.
	 *
	 * @param string $error Login error HTML.
	 * @return string
	 */
	public function generic_error( $error ) {
		if ( ! $this->enabled() ) {
			return $error;
		}

		if ( false !== strpos( (string) $error, 'teksecurity' ) ) {
			return $error;
		}

		if ( preg_match( '/(incorrect|unknown|invalid)/i', wp_strip_all_tags( (string) $error ) ) ) {
			return __( '<strong>Sign-in failed.</strong> Check the username and password and try again.', 'teksecurity' );
		}

		return $error;
	}

	/**
	 * Write a lockout row.
	 *
	 * @param string $ip       Address.
	 * @param string $username Last username tried.
	 * @param int    $tries    Failed attempts.
	 * @return void
	 */
	protected function lock_out( $ip, $username, $tries ) {
		global $wpdb;

		$minutes = max( 1, (int) Options::get( 'login.lockout', 30 ) );

		$table = Installer::table( 'lockouts' );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$table} (ip, country, username, tries, created_at, expires_at)
				 VALUES (%s, %s, %s, %d, %s, %s)
				 ON DUPLICATE KEY UPDATE tries = VALUES(tries), username = VALUES(username), expires_at = VALUES(expires_at)",
				$ip,
				Ip::country( $ip ),
				substr( sanitize_user( $username, true ), 0, 190 ),
				(int) $tries,
				current_time( 'mysql' ),
				gmdate( 'Y-m-d H:i:s', strtotime( '+' . $minutes . ' minutes', (int) current_time( 'timestamp' ) ) ) // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp
			)
		);
		// phpcs:enable
	}

	/**
	 * Active lockouts, newest first.
	 *
	 * @return array
	 */
	public static function lockouts() {
		global $wpdb;

		self::purge_expired();

		$table = Installer::table( 'lockouts' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results( "SELECT id, ip, country, username, tries, expires_at FROM {$table} ORDER BY expires_at DESC", ARRAY_A );

		return array_map(
			static function ( $row ) {
				return array(
					'id'        => (int) $row['id'],
					'ip'        => $row['ip'],
					'country'   => $row['country'],
					'username'  => $row['username'],
					'tries'     => (int) $row['tries'],
					'expiresAt' => $row['expires_at'],
					'until'     => mysql2date( 'H:i', $row['expires_at'] ),
				);
			},
			(array) $rows
		);
	}

	/**
	 * The active lockout for an IP, if any.
	 *
	 * @param string $ip Address.
	 * @return array|null
	 */
	public static function find_lock( $ip ) {
		global $wpdb;

		self::purge_expired();

		$table = Installer::table( 'lockouts' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT id, ip, username, tries, expires_at FROM {$table} WHERE ip = %s", $ip ), ARRAY_A );

		if ( ! $row ) {
			return null;
		}

		return array(
			'id'        => (int) $row['id'],
			'ip'        => $row['ip'],
			'username'  => $row['username'],
			'tries'     => (int) $row['tries'],
			'expiresAt' => $row['expires_at'],
		);
	}

	/**
	 * Release a lockout.
	 *
	 * @param int $id Row id.
	 * @return bool
	 */
	public static function unlock( $id ) {
		global $wpdb;

		return (bool) $wpdb->delete( Installer::table( 'lockouts' ), array( 'id' => (int) $id ), array( '%d' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Drop lockouts that have run out.
	 *
	 * @return void
	 */
	public static function purge_expired() {
		global $wpdb;

		$table = Installer::table( 'lockouts' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE expires_at < %s", current_time( 'mysql' ) ) );
	}
}
