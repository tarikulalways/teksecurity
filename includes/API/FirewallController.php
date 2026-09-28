<?php
/**
 * Firewall mode, per-module settings and rule exclusions.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Core\Options;
use TekSecurity\Helpers\Logger;
use TekSecurity\Helpers\Rules;
use TekSecurity\Modules\Firewall;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Routes for the Firewall screen.
 */
class FirewallController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/firewall',
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
					'args'                => array(
						'mode'    => array(
							'type' => 'string',
							'enum' => array( 'protect', 'learning', 'off' ),
						),
						'modules' => array( 'type' => 'object' ),
					),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/firewall/exclusions',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'add_exclusion' ),
					'permission_callback' => array( $this, 'permission' ),
					'args'                => array(
						'ruleId' => array(
							'type'     => 'string',
							'required' => true,
						),
						'path'   => array(
							'type'     => 'string',
							'required' => true,
						),
					),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/firewall/exclusions/(?P<id>\d+)',
			array(
				array(
					'methods'             => 'DELETE',
					'callback'            => array( $this, 'delete_exclusion' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);
	}

	/**
	 * Current firewall configuration.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_item( $request ) {
		unset( $request );

		$counts  = Logger::counts_by_type( 7 );
		$mode    = Options::get( 'firewall.mode', 'protect' );
		$rows    = array();
		$total   = 0;

		foreach ( Rules::modules() as $module ) {
			if ( 'firewall' !== $module['page'] ) {
				continue;
			}

			$key      = $module['key'];
			$settings = (array) Options::get( 'firewall.modules.' . $key, array() );
			$rules    = Rules::count( $key );
			$total   += $rules;

			$rows[] = array(
				'key'     => $key,
				'name'    => $module['name'],
				'icon'    => $module['icon'],
				'desc'    => $module['desc'],
				'rules'   => $rules,
				'matches' => isset( $counts[ $key ] ) ? $counts[ $key ] : 0,
				'on'      => ! empty( $settings['on'] ),
				'action'  => isset( $settings['act'] ) ? $settings['act'] : 'block',
			);
		}

		return new WP_REST_Response(
			array(
				'mode'       => $mode,
				'modules'    => $rows,
				'ruleTotal'  => $total,
				'exclusions' => Firewall::exclusions(),
			)
		);
	}

	/**
	 * Save the firewall mode and per-module settings.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function update_item( $request ) {
		$settings = Options::all();

		$mode = $request->get_param( 'mode' );
		if ( in_array( $mode, array( 'protect', 'learning', 'off' ), true ) ) {
			$settings['firewall']['mode'] = $mode;
		}

		$modules = $request->get_param( 'modules' );
		if ( is_array( $modules ) ) {
			foreach ( $modules as $key => $patch ) {
				$key = sanitize_key( $key );

				if ( ! isset( $settings['firewall']['modules'][ $key ] ) ) {
					continue;
				}

				if ( array_key_exists( 'on', (array) $patch ) ) {
					$settings['firewall']['modules'][ $key ]['on'] = rest_sanitize_boolean( $patch['on'] );
				}

				if ( isset( $patch['act'] ) && in_array( $patch['act'], array( 'block', 'log' ), true ) ) {
					$settings['firewall']['modules'][ $key ]['act'] = $patch['act'];
				}
			}
		}

		Options::save( $settings );

		return $this->get_item( $request );
	}

	/**
	 * Add a rule exclusion.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function add_exclusion( $request ) {
		Firewall::add_exclusion(
			(string) $request->get_param( 'ruleId' ),
			(string) $request->get_param( 'path' )
		);

		return new WP_REST_Response( array( 'exclusions' => Firewall::exclusions() ), 201 );
	}

	/**
	 * Remove a rule exclusion.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function delete_exclusion( $request ) {
		Firewall::remove_exclusion( (int) $request->get_param( 'id' ) );

		return new WP_REST_Response( array( 'exclusions' => Firewall::exclusions() ) );
	}
}
