<?php
/**
 * Traffic log.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Helpers\Logger;
use TekSecurity\Helpers\Rules;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Routes for the Traffic log screen and the request drawer.
 */
class TrafficController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/traffic',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_items' ),
					'permission_callback' => array( $this, 'permission' ),
					'args'                => array(
						'search'   => array( 'type' => 'string' ),
						'action'   => array(
							'type'    => 'string',
							'default' => 'all',
						),
						'type'     => array(
							'type'    => 'string',
							'default' => 'all',
						),
						'page'     => array(
							'type'    => 'integer',
							'default' => 0,
						),
						'per_page' => array(
							'type'    => 'integer',
							'default' => 12,
						),
					),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/traffic/(?P<id>\d+)',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_item' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/traffic/types',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_types' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);
	}

	/**
	 * A page of log rows.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_items( $request ) {
		$result = Logger::query(
			array(
				'search'   => (string) $request->get_param( 'search' ),
				'action'   => (string) $request->get_param( 'action' ),
				'type'     => (string) $request->get_param( 'type' ),
				'page'     => (int) $request->get_param( 'page' ),
				'per_page' => (int) $request->get_param( 'per_page' ),
			)
		);

		$per_page = max( 1, (int) $request->get_param( 'per_page' ) );

		return new WP_REST_Response(
			array(
				'rows'       => $result['rows'],
				'total'      => $result['total'],
				'page'       => (int) $request->get_param( 'page' ),
				'totalPages' => max( 1, (int) ceil( $result['total'] / $per_page ) ),
			)
		);
	}

	/**
	 * One event, with the drawer's explanation attached.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function get_item( $request ) {
		$event = Logger::find( (int) $request->get_param( 'id' ) );

		if ( ! $event ) {
			return new WP_Error(
				'teksecurity_event_not_found',
				__( 'That request is no longer in the log.', 'teksecurity' ),
				array( 'status' => 404 )
			);
		}

		$types  = Rules::types();
		$module = isset( $types[ $event['type'] ] ) ? $types[ $event['type'] ]['module'] : '';
		$names  = wp_list_pluck( Rules::modules(), 'name', 'key' );

		$event['typeLabel']  = isset( $types[ $event['type'] ] ) ? $types[ $event['type'] ]['label'] : $event['type'];
		$event['explain']    = isset( $types[ $event['type'] ] ) ? $types[ $event['type'] ]['explain'] : '';
		$event['moduleName'] = isset( $names[ $module ] ) ? $names[ $module ] : '';

		return new WP_REST_Response( $event );
	}

	/**
	 * The attack types, for the filter dropdown.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_types( $request ) {
		unset( $request );

		$out = array();

		foreach ( Rules::types() as $key => $type ) {
			$out[] = array(
				'key'   => $key,
				'label' => $type['label'],
			);
		}

		return new WP_REST_Response( $out );
	}
}
