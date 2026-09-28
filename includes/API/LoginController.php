<?php
/**
 * Login protection settings and lockouts.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Core\Options;
use TekSecurity\Helpers\Logger;
use TekSecurity\Modules\Login;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Routes for the Login protection screen.
 */
class LoginController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/login',
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
			'/login/lockouts/(?P<id>\d+)',
			array(
				array(
					'methods'             => 'DELETE',
					'callback'            => array( $this, 'unlock' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);
	}

	/**
	 * Settings, lockouts and the module status.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_item( $request ) {
		unset( $request );

		$counts = Logger::counts_by_type( 7 );

		return new WP_REST_Response(
			array(
				'enabled'  => (bool) Options::get( 'firewall.modules.brute.on', true ),
				'attempts' => (int) Options::get( 'login.attempts', 5 ),
				'lockout'  => (string) Options::get( 'login.lockout', '30' ),
				'window'   => (string) Options::get( 'login.window', '15' ),
				'blockAdmin' => (bool) Options::get( 'login.block_admin', true ),
				'xmlrpc'   => (bool) Options::get( 'login.xmlrpc', true ),
				'lockouts' => Login::lockouts(),
				'stopped'  => isset( $counts['brute'] ) ? $counts['brute'] : 0,
				// The guard never locks out a username that really exists, or
				// the owner of an "admin" account could never sign in again.
				'adminUserExists' => (bool) username_exists( 'admin' ),
			)
		);
	}

	/**
	 * Save the lockout rules.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function update_item( $request ) {
		$settings = Options::all();

		if ( null !== $request->get_param( 'enabled' ) ) {
			$settings['firewall']['modules']['brute']['on'] = $this->bool( $request, 'enabled', true );
		}

		if ( null !== $request->get_param( 'attempts' ) ) {
			$settings['login']['attempts'] = max( 2, min( 20, (int) $request->get_param( 'attempts' ) ) );
		}

		foreach ( array( 'lockout', 'window' ) as $key ) {
			if ( null !== $request->get_param( $key ) ) {
				$settings['login'][ $key ] = (string) absint( $request->get_param( $key ) );
			}
		}

		if ( null !== $request->get_param( 'blockAdmin' ) ) {
			$settings['login']['block_admin'] = $this->bool( $request, 'blockAdmin', true );
		}

		if ( null !== $request->get_param( 'xmlrpc' ) ) {
			$settings['login']['xmlrpc'] = $this->bool( $request, 'xmlrpc', true );
		}

		Options::save( $settings );

		return $this->get_item( $request );
	}

	/**
	 * Release a lockout.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function unlock( $request ) {
		Login::unlock( (int) $request->get_param( 'id' ) );

		return new WP_REST_Response( array( 'lockouts' => Login::lockouts() ) );
	}
}
