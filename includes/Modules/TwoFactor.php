<?php
/**
 * Two-factor authentication.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Modules;

use TekSecurity\Core\Options;
use TekSecurity\Helpers\Logger;
use TekSecurity\Helpers\Totp;
use WP_Error;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Adds a second step to the login of every user who is required to use it.
 */
class TwoFactor {

	const META_REQUIRED  = '_teksec_2fa_required';
	const META_METHOD    = '_teksec_2fa_method';
	const META_SECRET    = '_teksec_2fa_secret';
	const META_PENDING   = '_teksec_2fa_pending_secret';
	const META_BACKUP    = '_teksec_2fa_backup_codes';
	const META_ENABLED_AT = '_teksec_2fa_enabled_at';
	const META_REMINDED  = '_teksec_2fa_reminded_at';
	const META_TRUSTED   = '_teksec_2fa_trusted';
	const META_EMAIL_CODE = '_teksec_2fa_email_code';

	const META_LOGIN_TOKEN = '_teksec_2fa_login_token';

	const COOKIE_TRUSTED = 'teksec_2fa_trusted';

	/** Minutes a half-finished login may sit before the token dies. */
	const TOKEN_LIFETIME = 10;

	/** Wrong codes allowed before the token is destroyed. */
	const MAX_CODE_ATTEMPTS = 5;

	/**
	 * Hook in.
	 *
	 * @return void
	 */
	public function register() {
		add_filter( 'authenticate', array( $this, 'intercept' ), 50, 3 );
		add_action( 'show_user_profile', array( $this, 'profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'profile_section' ) );
	}

	/**
	 * Whether two-factor is switched on site-wide.
	 *
	 * @return bool
	 */
	public static function enabled() {
		// An emergency way back in: define TEKSEC_DISABLE_2FA in wp-config.php.
		if ( defined( 'TEKSEC_DISABLE_2FA' ) && TEKSEC_DISABLE_2FA ) {
			return false;
		}

		return (bool) Options::get( 'twofactor.on', true );
	}

	/**
	 * Whether a user must use two-factor.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_required( $user_id ) {
		return self::enabled() && '1' === (string) get_user_meta( $user_id, self::META_REQUIRED, true );
	}

	/**
	 * The active method for a user: app, email or none.
	 *
	 * @param int $user_id User id.
	 * @return string
	 */
	public static function method( $user_id ) {
		$method = (string) get_user_meta( $user_id, self::META_METHOD, true );

		return in_array( $method, array( 'app', 'email' ), true ) ? $method : 'none';
	}

	/**
	 * Whether the user has finished setting two-factor up.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_configured( $user_id ) {
		return 'none' !== self::method( $user_id );
	}

	/**
	 * The date by which a user must finish setting up, or null when there is no grace period.
	 *
	 * @param int $user_id User id.
	 * @return int|null Unix timestamp.
	 */
	public static function due_at( $user_id ) {
		$grace = (int) Options::get( 'twofactor.grace', 7 );

		if ( 0 === $grace ) {
			return null;
		}

		$user = get_userdata( $user_id );
		$from = $user ? strtotime( $user->user_registered ) : time();
		$from = max( $from, (int) get_option( 'teksecurity_installed_at', time() ) );

		return $from + $grace * DAY_IN_SECONDS;
	}

	/* --------------------------------------------------------------------- *
	 * Login flow
	 * --------------------------------------------------------------------- */

	/**
	 * Hold the login at the password step and hand it to the second-step screen.
	 *
	 * The password is right, but the auth cookie is not issued here. A one-time
	 * login token is stored against the user and the browser is sent to the
	 * challenge screen, which finishes the login once the code checks out. That
	 * way every entry point — wp-login.php, a theme template, WooCommerce, a
	 * custom form — behaves the same, because they all land on one screen.
	 *
	 * @param null|WP_User|WP_Error $user     Result so far.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return null|WP_User|WP_Error
	 */
	public function intercept( $user, $username, $password ) {
		unset( $username, $password );

		if ( ! ( $user instanceof WP_User ) || ! self::enabled() ) {
			return $user;
		}

		if ( self::is_machine_request() ) {
			return $user;
		}

		if ( ! self::is_required( $user->ID ) ) {
			return $user;
		}

		if ( $this->device_is_trusted( $user->ID ) ) {
			return $user;
		}

		// A form that already carries the code can finish in one step, which
		// keeps a single-page custom login working with no redirect at all.
		//
		// No nonce here on purpose: this runs inside core's `authenticate`
		// filter, on the same POST core itself processes without one, and any
		// login form - core's or a theme's - would break if one were demanded.
		// Nothing is written or changed; the code is only compared, and the
		// request has already proved it knows the password. The plugin's own
		// second-step screens do carry and verify a nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( self::is_configured( $user->ID ) && isset( $_POST['teksec_2fa_code'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$code = sanitize_text_field( wp_unslash( $_POST['teksec_2fa_code'] ) );

			if ( self::verify_code( $user->ID, $code ) ) {
				return $user;
			}

			return new WP_Error(
				'teksecurity_2fa_invalid',
				__( '<strong>That code didn’t match.</strong> Codes change every 30 seconds, so try the newest one.', 'teksecurity' )
			);
		}

		if ( self::is_configured( $user->ID ) ) {
			$this->hand_off( $user, 'teksec_2fa' );
		}

		// Not enrolled. Inside the grace period they carry on with a password;
		// once the deadline passes they must set two-factor up to get in.
		$due = self::due_at( $user->ID );

		if ( null === $due || time() >= $due ) {
			$this->hand_off( $user, 'teksec_enrol' );
		}

		return $user;
	}

	/**
	 * Send the browser to the second-step screen and stop.
	 *
	 * @param WP_User $user   The user whose password was accepted.
	 * @param string  $action Screen to show: teksec_2fa or teksec_enrol.
	 * @return void
	 */
	protected function hand_off( WP_User $user, $action ) {
		// Nothing of this half-finished login may survive in the browser.
		wp_clear_auth_cookie();

		if ( 'email' === self::method( $user->ID ) ) {
			$this->send_email_code( $user );
		}

		$token = self::issue_login_token( $user->ID, self::intended_redirect( $user ) );

		wp_safe_redirect(
			add_query_arg(
				array(
					'action'       => $action,
					'teksec_user'  => $user->ID,
					'teksec_token' => rawurlencode( $token ),
				),
				wp_login_url()
			)
		);
		exit;
	}

	/**
	 * Where to send the user once the second step passes.
	 *
	 * @param WP_User $user The user signing in.
	 * @return string
	 */
	protected static function intended_redirect( WP_User $user ) {
		// phpcs:ignore WordPress.Security.NonceVerification
		$requested = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';

		if ( '' === $requested ) {
			// A custom login form usually posts to the page it lives on, so
			// coming back to that page is the least surprising outcome.
			$referer = wp_get_referer();

			if ( $referer && false === strpos( $referer, 'wp-login.php' ) ) {
				$requested = $referer;
			}
		}

		if ( '' === $requested ) {
			$requested = user_can( $user, 'read' ) ? admin_url() : home_url();
		}

		/**
		 * This is core's own filter, fired here so a site that already changes
		 * where people land after signing in keeps working.
		 *
		 * This filter is documented in wp-login.php
		 */
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
		return apply_filters( 'login_redirect', $requested, $requested, $user );
	}

	/**
	 * Whether this request authenticated with a machine credential.
	 *
	 * Application passwords, the REST API and XML-RPC cannot show a code
	 * screen. An application password is itself a per-client credential the
	 * owner can revoke on its own, so it stands in for the second factor.
	 *
	 * @return bool
	 */
	public static function is_machine_request() {
		$machine = ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| ! empty( $GLOBALS['wp_rest_application_password_uuid'] );

		/**
		 * Filter whether two-factor is skipped for this request.
		 *
		 * @param bool $machine Whether the request used a machine credential.
		 */
		return (bool) apply_filters( 'teksecurity_2fa_skip', $machine );
	}

	/* --------------------------------------------------------------------- *
	 * Login tokens
	 * --------------------------------------------------------------------- */

	/**
	 * Mint a one-time token that stands for "this password was correct".
	 *
	 * @param int    $user_id     User id.
	 * @param string $redirect_to Where to go once the code checks out.
	 * @return string The raw token, for the URL.
	 */
	public static function issue_login_token( $user_id, $redirect_to = '' ) {
		$token = wp_generate_password( 32, false, false );

		update_user_meta(
			$user_id,
			self::META_LOGIN_TOKEN,
			array(
				'hash'     => wp_hash_password( $token ),
				'expires'  => time() + self::TOKEN_LIFETIME * MINUTE_IN_SECONDS,
				'redirect' => $redirect_to,
				'failures' => 0,
			)
		);

		return $token;
	}

	/**
	 * Check a login token without spending it.
	 *
	 * @param int    $user_id User id.
	 * @param string $token   Raw token from the URL.
	 * @return array|null The stored entry, or null when it is no good.
	 */
	public static function check_login_token( $user_id, $token ) {
		$stored = get_user_meta( $user_id, self::META_LOGIN_TOKEN, true );

		if ( ! is_array( $stored ) || empty( $stored['hash'] ) ) {
			return null;
		}

		if ( $stored['expires'] < time() ) {
			delete_user_meta( $user_id, self::META_LOGIN_TOKEN );
			return null;
		}

		if ( ! wp_check_password( (string) $token, $stored['hash'] ) ) {
			return null;
		}

		return $stored;
	}

	/**
	 * Spend a login token so it cannot be replayed.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function consume_login_token( $user_id ) {
		delete_user_meta( $user_id, self::META_LOGIN_TOKEN );
	}

	/**
	 * Count a wrong code, and give up on this login once there are too many.
	 *
	 * @param int $user_id User id.
	 * @return int Attempts left. Zero means the token was destroyed.
	 */
	public static function register_failure( $user_id ) {
		$stored = get_user_meta( $user_id, self::META_LOGIN_TOKEN, true );

		if ( ! is_array( $stored ) ) {
			return 0;
		}

		$stored['failures'] = (int) $stored['failures'] + 1;
		$left               = self::MAX_CODE_ATTEMPTS - $stored['failures'];

		if ( $left > 0 ) {
			update_user_meta( $user_id, self::META_LOGIN_TOKEN, $stored );
			return $left;
		}

		self::consume_login_token( $user_id );

		$user = get_userdata( $user_id );

		Logger::record(
			array(
				'attack_type' => 'brute',
				'rule_id'     => 'TS-BF-7005',
				'rule_name'   => 'Two-factor code guessing',
				'action'      => 'blocked',
				'method'      => Firewall::method(),
				'path'        => Firewall::uri(),
				'matched_in'  => 'teksec_2fa_code (body)',
				'payload'     => sprintf(
					'%1$d wrong codes for %2$s',
					(int) $stored['failures'],
					$user ? $user->user_login : (string) $user_id
				),
			)
		);

		/**
		 * Fires when a login is abandoned for too many wrong codes.
		 *
		 * @param int $user_id User id.
		 */
		do_action( 'teksecurity_2fa_attempts_exhausted', $user_id );

		return 0;
	}

	/**
	 * Check a submitted code against the app secret, an email code or a backup code.
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted value.
	 * @return bool
	 */
	public static function verify_code( $user_id, $code ) {
		$code    = trim( (string) $code );
		$methods = (array) Options::get( 'twofactor.methods', array() );

		if ( 'app' === self::method( $user_id ) && ! empty( $methods['app'] ) ) {
			$secret = (string) get_user_meta( $user_id, self::META_SECRET, true );

			if ( $secret && Totp::verify( $secret, $code ) ) {
				return true;
			}
		}

		if ( 'email' === self::method( $user_id ) && ! empty( $methods['email'] ) ) {
			$stored = get_user_meta( $user_id, self::META_EMAIL_CODE, true );

			if ( is_array( $stored ) && $stored['expires'] > time() && hash_equals( (string) $stored['code'], preg_replace( '/\D/', '', $code ) ) ) {
				delete_user_meta( $user_id, self::META_EMAIL_CODE );
				return true;
			}
		}

		if ( ! empty( $methods['backup'] ) && self::consume_backup_code( $user_id, $code ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Mail a one-time code to the account address.
	 *
	 * @param WP_User $user User.
	 * @return void
	 */
	protected function send_email_code( WP_User $user ) {
		$existing = get_user_meta( $user->ID, self::META_EMAIL_CODE, true );

		if ( is_array( $existing ) && $existing['expires'] > time() - 60 && $existing['expires'] > time() ) {
			return; // A fresh code is already on its way.
		}

		$code = str_pad( (string) wp_rand( 0, 999999 ), 6, '0', STR_PAD_LEFT );

		update_user_meta(
			$user->ID,
			self::META_EMAIL_CODE,
			array(
				'code'    => $code,
				'expires' => time() + 10 * MINUTE_IN_SECONDS,
			)
		);

		wp_mail(
			$user->user_email,
			sprintf(
				/* translators: %s: site name. */
				__( 'Your %s sign-in code', 'teksecurity' ),
				wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			),
			sprintf(
				/* translators: 1: six-digit code, 2: site name. */
				__( "Your sign-in code is %1\$s.\n\nIt expires in 10 minutes. If you did not try to sign in to %2\$s, change your password.", 'teksecurity' ),
				$code,
				home_url()
			)
		);
	}

	/**
	 * Send another email code on request.
	 *
	 * send_email_code() already refuses to send twice inside a minute, so this
	 * cannot be used to flood the address.
	 *
	 * @param WP_User $user The user signing in.
	 * @return void
	 */
	public static function resend_email_code( WP_User $user ) {
		$instance = new self();
		$instance->send_email_code( $user );
	}

	/* --------------------------------------------------------------------- *
	 * Setup
	 * --------------------------------------------------------------------- */

	/**
	 * Start app enrolment: create a pending secret and return the scan data.
	 *
	 * @param int  $user_id User id.
	 * @param bool $fresh   Mint a new secret, or reuse a pending one.
	 * @return array
	 */
	public static function begin_setup( $user_id, $fresh = true ) {
		$user   = get_userdata( $user_id );
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$secret = (string) get_user_meta( $user_id, self::META_PENDING, true );

		// A screen that re-renders — after a wrong code, say — must keep
		// offering the same secret, or the QR the user just scanned stops
		// matching the code their app is showing.
		if ( $fresh || '' === $secret ) {
			$secret = Totp::secret();
		}

		update_user_meta( $user_id, self::META_PENDING, $secret );

		return array(
			'secret'      => $secret,
			'prettySecret' => Totp::pretty( $secret ),
			'uri'         => Totp::uri( $secret, $user ? $user->user_email : (string) $user_id, $issuer ),
		);
	}

	/**
	 * Confirm enrolment with the first code from the app.
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted code.
	 * @return true|WP_Error
	 */
	public static function confirm_setup( $user_id, $code ) {
		$code = preg_replace( '/\D/', '', (string) $code );

		if ( 6 !== strlen( $code ) ) {
			return new WP_Error(
				'teksecurity_2fa_length',
				__( 'Enter the 6-digit code from your app.', 'teksecurity' ),
				array( 'status' => 400 )
			);
		}

		$secret = (string) get_user_meta( $user_id, self::META_PENDING, true );

		if ( '' === $secret ) {
			return new WP_Error(
				'teksecurity_2fa_no_pending',
				__( 'Start the setup again — the pending code has expired.', 'teksecurity' ),
				array( 'status' => 409 )
			);
		}

		if ( ! Totp::verify( $secret, $code ) ) {
			return new WP_Error(
				'teksecurity_2fa_mismatch',
				__( 'That code didn’t match. Codes change every 30 seconds, so try the newest one.', 'teksecurity' ),
				array( 'status' => 400 )
			);
		}

		delete_user_meta( $user_id, self::META_PENDING );
		update_user_meta( $user_id, self::META_SECRET, $secret );
		update_user_meta( $user_id, self::META_METHOD, 'app' );
		update_user_meta( $user_id, self::META_ENABLED_AT, time() );

		/**
		 * Fires after a user finishes two-factor enrolment.
		 *
		 * @param int    $user_id User id.
		 * @param string $method  app|email.
		 */
		do_action( 'teksecurity_2fa_enabled', $user_id, 'app' );

		return true;
	}

	/**
	 * Switch a user to email codes, which need no enrolment.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function enable_email( $user_id ) {
		update_user_meta( $user_id, self::META_METHOD, 'email' );
		update_user_meta( $user_id, self::META_ENABLED_AT, time() );

		do_action( 'teksecurity_2fa_enabled', $user_id, 'email' );
	}

	/**
	 * Turn two-factor off for a user and forget their secret.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function reset( $user_id ) {
		foreach ( array( self::META_METHOD, self::META_SECRET, self::META_PENDING, self::META_BACKUP, self::META_ENABLED_AT, self::META_TRUSTED, self::META_EMAIL_CODE ) as $meta ) {
			delete_user_meta( $user_id, $meta );
		}

		do_action( 'teksecurity_2fa_reset', $user_id );
	}

	/**
	 * Generate ten fresh backup codes, storing only their hashes.
	 *
	 * @param int $user_id User id.
	 * @return array Plain codes, shown once.
	 */
	public static function generate_backup_codes( $user_id ) {
		$plain  = array();
		$hashes = array();

		for ( $i = 0; $i < 10; $i++ ) {
			$code    = sprintf( '%04d-%04d', wp_rand( 0, 9999 ), wp_rand( 0, 9999 ) );
			$plain[] = $code;
			$hashes[] = wp_hash_password( $code );
		}

		update_user_meta( $user_id, self::META_BACKUP, $hashes );

		return $plain;
	}

	/**
	 * Spend a backup code.
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted value.
	 * @return bool
	 */
	protected static function consume_backup_code( $user_id, $code ) {
		$hashes = (array) get_user_meta( $user_id, self::META_BACKUP, true );

		if ( ! $hashes ) {
			return false;
		}

		// Codes are stored the way WordPress stores passwords, so they must be
		// checked the same way: wp_check_password() understands both the modern
		// bcrypt format and the older phpass hashes from an earlier install.
		$code = strtoupper( trim( $code ) );

		foreach ( $hashes as $index => $hash ) {
			if ( wp_check_password( $code, $hash ) ) {
				unset( $hashes[ $index ] );
				update_user_meta( $user_id, self::META_BACKUP, array_values( $hashes ) );

				/**
				 * Fires when a two-factor backup code is spent.
				 *
				 * @param int $user_id User id.
				 * @param int $left    Codes still unused.
				 */
				do_action( 'teksecurity_backup_code_used', $user_id, count( $hashes ) );

				return true;
			}
		}

		return false;
	}

	/**
	 * How many backup codes are left.
	 *
	 * @param int $user_id User id.
	 * @return int
	 */
	public static function backup_codes_left( $user_id ) {
		return count( (array) get_user_meta( $user_id, self::META_BACKUP, true ) );
	}

	/* --------------------------------------------------------------------- *
	 * Trusted devices
	 * --------------------------------------------------------------------- */

	/**
	 * Whether this browser was trusted inside the remember window.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	protected function device_is_trusted( $user_id ) {
		$days = (int) Options::get( 'twofactor.remember', 30 );

		if ( 0 === $days || empty( $_COOKIE[ self::COOKIE_TRUSTED ] ) ) {
			return false;
		}

		$token   = sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE_TRUSTED ] ) );
		$trusted = (array) get_user_meta( $user_id, self::META_TRUSTED, true );

		foreach ( $trusted as $entry ) {
			if ( isset( $entry['token'], $entry['expires'] ) && hash_equals( (string) $entry['token'], $token ) && $entry['expires'] > time() ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Remember this browser so it skips the code next time.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function trust_device( $user_id ) {
		$days = (int) Options::get( 'twofactor.remember', 30 );

		if ( 0 === $days ) {
			return;
		}

		$token   = wp_generate_password( 40, false, false );
		$expires = time() + $days * DAY_IN_SECONDS;

		$trusted = array_values(
			array_filter(
				(array) get_user_meta( $user_id, self::META_TRUSTED, true ),
				static function ( $entry ) {
					return isset( $entry['expires'] ) && $entry['expires'] > time();
				}
			)
		);

		$trusted[] = array(
			'token'   => $token,
			'expires' => $expires,
		);

		update_user_meta( $user_id, self::META_TRUSTED, array_slice( $trusted, -10 ) );

		setcookie( self::COOKIE_TRUSTED, $token, $expires, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, is_ssl(), true );
	}

	/* --------------------------------------------------------------------- *
	 * Admin listings
	 * --------------------------------------------------------------------- */

	/**
	 * Every user required to use two-factor, shaped for the admin.
	 *
	 * @return array
	 */
	public static function required_users() {
		$query = new \WP_User_Query(
			array(
				'meta_key'   => self::META_REQUIRED, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_value' => '1', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'number'     => 500,
				'orderby'    => 'display_name',
			)
		);

		return array_map( array( __CLASS__, 'shape_user' ), $query->get_results() );
	}

	/**
	 * Users in a role who are not yet required to use two-factor.
	 *
	 * @param string $role Role key.
	 * @return array
	 */
	public static function available_users( $role ) {
		$query = new \WP_User_Query(
			array(
				'role'    => $role,
				'number'  => 500,
				'orderby' => 'display_name',
			)
		);

		$out = array();
		foreach ( $query->get_results() as $user ) {
			if ( self::is_required( $user->ID ) ) {
				continue;
			}
			$out[] = array(
				'id'    => $user->ID,
				'name'  => $user->display_name,
				'email' => $user->user_email,
			);
		}

		return $out;
	}

	/**
	 * Shape a user for the REST response.
	 *
	 * @param WP_User $user User.
	 * @return array
	 */
	public static function shape_user( WP_User $user ) {
		$method  = self::method( $user->ID );
		$roles   = array_values( $user->roles );
		$role    = $roles ? $roles[0] : '';
		$due     = self::due_at( $user->ID );
		$names   = wp_roles()->get_names();

		return array(
			'id'          => $user->ID,
			'name'        => $user->display_name,
			'email'       => $user->user_email,
			'role'        => $role,
			'roleName'    => isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : $role,
			'initials'    => self::initials( $user->display_name ),
			'status'      => $method,
			'self'        => get_current_user_id() === $user->ID,
			'required'    => self::is_required( $user->ID ),
			'dueAt'       => $due ? gmdate( 'c', $due ) : null,
			'reminded'    => (bool) get_user_meta( $user->ID, self::META_REMINDED, true ),
			'backupLeft'  => self::backup_codes_left( $user->ID ),
		);
	}

	/**
	 * Initials for the avatar chip.
	 *
	 * @param string $name Display name.
	 * @return string
	 */
	protected static function initials( $name ) {
		$parts = preg_split( '/\s+/', trim( (string) $name ) );
		$out   = '';

		foreach ( array_slice( (array) $parts, 0, 2 ) as $part ) {
			$out .= mb_strtoupper( mb_substr( $part, 0, 1 ) );
		}

		return '' === $out ? '?' : $out;
	}

	/**
	 * Mail a setup reminder.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function send_reminder( $user_id ) {
		$user = get_userdata( $user_id );

		if ( ! $user ) {
			return false;
		}

		$due  = self::due_at( $user_id );
		$body = sprintf(
			/* translators: 1: site name, 2: profile URL. */
			__( "Your account on %1\$s needs two-factor authentication.\n\nSet it up here: %2\$s", 'teksecurity' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			admin_url( 'admin.php?page=teksecurity#/twofa' )
		);

		if ( $due ) {
			$body .= "\n\n" . sprintf(
				/* translators: %s: formatted date. */
				__( 'Please finish by %s.', 'teksecurity' ),
				date_i18n( get_option( 'date_format' ), $due )
			);
		}

		$sent = wp_mail(
			$user->user_email,
			__( 'Set up two-factor authentication', 'teksecurity' ),
			$body
		);

		if ( $sent ) {
			update_user_meta( $user_id, self::META_REMINDED, time() );
		}

		return $sent;
	}

	/**
	 * Require or release a user.
	 *
	 * @param int  $user_id  User id.
	 * @param bool $required Whether two-factor is required.
	 * @return void
	 */
	public static function set_required( $user_id, $required ) {
		if ( $required ) {
			update_user_meta( $user_id, self::META_REQUIRED, '1' );
		} else {
			delete_user_meta( $user_id, self::META_REQUIRED );
			delete_user_meta( $user_id, self::META_REMINDED );
		}
	}

	/**
	 * Show the two-factor state on the user profile screen.
	 *
	 * @param WP_User $user User being edited.
	 * @return void
	 */
	public function profile_section( $user ) {
		if ( ! self::enabled() ) {
			return;
		}

		$configured = self::is_configured( $user->ID );
		?>
		<h2><?php esc_html_e( 'Two-factor authentication', 'teksecurity' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Status', 'teksecurity' ); ?></th>
				<td>
					<p>
						<?php
						if ( ! self::is_required( $user->ID ) ) {
							esc_html_e( 'Not required for this account.', 'teksecurity' );
						} elseif ( $configured ) {
							printf(
								/* translators: %s: method name. */
								esc_html__( 'Active using %s.', 'teksecurity' ),
								'app' === self::method( $user->ID ) ? esc_html__( 'an authenticator app', 'teksecurity' ) : esc_html__( 'email codes', 'teksecurity' )
							);
						} else {
							esc_html_e( 'Required, but not set up yet.', 'teksecurity' );
						}
						?>
					</p>
					<p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=teksecurity#/twofa' ) ); ?>">
							<?php esc_html_e( 'Manage in TekSecurity', 'teksecurity' ); ?>
						</a>
					</p>
				</td>
			</tr>
		</table>
		<?php
	}
}
