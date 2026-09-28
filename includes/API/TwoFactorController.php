<?php
/**
 * Two-factor authentication.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Core\Options;
use TekSecurity\Modules\TwoFactor;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Routes for the Two-factor auth screen and the enrolment modal.
 */
class TwoFactorController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/twofa',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_item' ),
					'permission_callback' => array( $this, 'permission' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'update_item' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/twofa/roles',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_roles' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/twofa/roles/(?P<role>[\w\-]+)/users',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_available_users' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/twofa/users',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'add_users' ),
					'permission_callback' => array( $this, 'permission' ),
					'args'                => array(
						'userIds' => array(
							'type'     => 'array',
							'required' => true,
							'items'    => array( 'type' => 'integer' ),
						),
					),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/twofa/users/(?P<id>\d+)',
			array(
				array(
					'methods'             => 'DELETE',
					'callback'            => array( $this, 'remove_user' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/twofa/users/(?P<id>\d+)/remind',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'remind' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/twofa/users/(?P<id>\d+)/reset',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'reset' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/twofa/setup',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'begin_setup' ),
					'permission_callback' => array( $this, 'self_permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/twofa/setup/verify',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'verify_setup' ),
					'permission_callback' => array( $this, 'self_permission' ),
					'args'                => array(
						'code' => array(
							'type'     => 'string',
							'required' => true,
						),
					),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/twofa/backup-codes',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'backup_codes' ),
					'permission_callback' => array( $this, 'self_permission' ),
				),
			)
		);
	}

	/**
	 * Settings, methods and the user list.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_item( $request ) {
		unset( $request );

		$users   = TwoFactor::required_users();
		$missing = count(
			array_filter(
				$users,
				static function ( $user ) {
					return 'none' === $user['status'];
				}
			)
		);

		return new WP_REST_Response(
			array(
				'enabled'  => TwoFactor::enabled(),
				'methods'  => (array) Options::get( 'twofactor.methods', array() ),
				'grace'    => (string) Options::get( 'twofactor.grace', '7' ),
				'remember' => (string) Options::get( 'twofactor.remember', '30' ),
				'users'    => $users,
				'missing'  => $missing,
			)
		);
	}

	/**
	 * Save the module settings.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function update_item( $request ) {
		$settings = Options::all();

		if ( null !== $request->get_param( 'enabled' ) ) {
			$settings['twofactor']['on'] = $this->bool( $request, 'enabled', true );
		}

		$methods = $request->get_param( 'methods' );
		if ( is_array( $methods ) ) {
			$next = $settings['twofactor']['methods'];

			foreach ( array( 'app', 'email', 'backup' ) as $key ) {
				if ( array_key_exists( $key, $methods ) ) {
					$next[ $key ] = rest_sanitize_boolean( $methods[ $key ] );
				}
			}

			if ( empty( $next['app'] ) && empty( $next['email'] ) ) {
				return new WP_Error(
					'teksecurity_no_method',
					__( 'Keep at least one sign-in method on.', 'teksecurity' ),
					array( 'status' => 400 )
				);
			}

			$settings['twofactor']['methods'] = $next;
		}

		foreach ( array( 'grace', 'remember' ) as $key ) {
			if ( null !== $request->get_param( $key ) ) {
				$settings['twofactor'][ $key ] = (string) absint( $request->get_param( $key ) );
			}
		}

		Options::save( $settings );

		return $this->get_item( $request );
	}

	/**
	 * Every role on the site, with its user count.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_roles( $request ) {
		unset( $request );

		$counts = count_users();
		$out    = array();

		foreach ( wp_roles()->get_names() as $key => $name ) {
			$out[] = array(
				'key'   => $key,
				'name'  => translate_user_role( $name ),
				'users' => isset( $counts['avail_roles'][ $key ] ) ? (int) $counts['avail_roles'][ $key ] : 0,
			);
		}

		return new WP_REST_Response( $out );
	}

	/**
	 * Users in a role who are not required yet.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_available_users( $request ) {
		return new WP_REST_Response( TwoFactor::available_users( sanitize_key( $request->get_param( 'role' ) ) ) );
	}

	/**
	 * Require two-factor for a set of users.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function add_users( $request ) {
		foreach ( (array) $request->get_param( 'userIds' ) as $id ) {
			TwoFactor::set_required( (int) $id, true );
		}

		return $this->get_item( $request );
	}

	/**
	 * Release a user from the requirement.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function remove_user( $request ) {
		TwoFactor::set_required( (int) $request->get_param( 'id' ), false );

		return $this->get_item( $request );
	}

	/**
	 * Mail a setup reminder.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function remind( $request ) {
		$sent = TwoFactor::send_reminder( (int) $request->get_param( 'id' ) );

		if ( ! $sent ) {
			return new WP_Error(
				'teksecurity_reminder_failed',
				__( 'The reminder could not be sent. Check that this site can send email.', 'teksecurity' ),
				array( 'status' => 500 )
			);
		}

		return $this->get_item( $request );
	}

	/**
	 * Clear a user's two-factor setup.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function reset( $request ) {
		TwoFactor::reset( (int) $request->get_param( 'id' ) );

		return $this->get_item( $request );
	}

	/**
	 * Start enrolment for the signed-in user.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function begin_setup( $request ) {
		unset( $request );

		$user_id = get_current_user_id();
		$methods = (array) Options::get( 'twofactor.methods', array() );

		if ( empty( $methods['app'] ) ) {
			TwoFactor::enable_email( $user_id );

			return new WP_REST_Response(
				array(
					'method' => 'email',
					'done'   => true,
				)
			);
		}

		$setup = TwoFactor::begin_setup( $user_id );

		return new WP_REST_Response(
			array(
				'method'       => 'app',
				'done'         => false,
				'prettySecret' => $setup['prettySecret'],
				'uri'          => $setup['uri'],
				'steps'        => empty( $methods['backup'] ) ? 2 : 3,
			)
		);
	}

	/**
	 * Confirm enrolment with the first code.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function verify_setup( $request ) {
		$result = TwoFactor::confirm_setup( get_current_user_id(), (string) $request->get_param( 'code' ) );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return new WP_REST_Response( array( 'verified' => true ) );
	}

	/**
	 * Issue ten fresh backup codes for the signed-in user.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function backup_codes( $request ) {
		unset( $request );

		return new WP_REST_Response( array( 'codes' => TwoFactor::generate_backup_codes( get_current_user_id() ) ) );
	}
}
