<?php
/**
 * Blocklist and allowlist.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Helpers\IpList;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Routes for the IP lists screen.
 */
class IpsController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/ips',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_items' ),
					'permission_callback' => array( $this, 'permission' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'create_item' ),
					'permission_callback' => array( $this, 'permission' ),
					'args'                => array(
						'list' => array(
							'type'    => 'string',
							'enum'    => array( 'block', 'allow' ),
							'default' => 'block',
						),
						'ip'   => array(
							'type'     => 'string',
							'required' => true,
						),
						'note' => array( 'type' => 'string' ),
					),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/ips/(?P<id>\d+)',
			array(
				array(
					'methods'             => 'DELETE',
					'callback'            => array( $this, 'delete_item' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);
	}

	/**
	 * Both lists.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_items( $request ) {
		unset( $request );

		return new WP_REST_Response(
			array(
				'block' => IpList::all( 'block' ),
				'allow' => IpList::all( 'allow' ),
			)
		);
	}

	/**
	 * Add an address.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|\WP_Error
	 */
	public function create_item( $request ) {
		$result = IpList::add(
			(string) $request->get_param( 'list' ),
			(string) $request->get_param( 'ip' ),
			(string) $request->get_param( 'note' )
		);

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$response = $this->get_items( $request );
		$response->set_status( 201 );

		return $response;
	}

	/**
	 * Remove an address.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function delete_item( $request ) {
		IpList::remove( (int) $request->get_param( 'id' ) );

		return $this->get_items( $request );
	}
}
