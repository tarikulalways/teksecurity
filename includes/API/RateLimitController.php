<?php
/**
 * Rate limiting settings.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Core\Options;
use TekSecurity\Helpers\Logger;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Routes for the Rate limiting screen.
 */
class RateLimitController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/ratelimit',
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
	}

	/**
	 * Current limits.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_item( $request ) {
		unset( $request );

		$counts = Logger::counts_by_type( 7 );

		return new WP_REST_Response(
			array(
				'enabled' => (bool) Options::get( 'firewall.modules.rate.on', true ),
				'preset'  => (string) Options::get( 'ratelimit.preset', 'balanced' ),
				'action'  => (string) Options::get( 'ratelimit.act', 'throttle' ),
				'bypass'  => (bool) Options::get( 'ratelimit.bypass', true ),
				'rules'   => array_map(
					static function ( $rule ) {
						$rule['name'] = Options::rule_label( $rule['key'], $rule['name'] );
						return $rule;
					},
					array_values( (array) Options::get( 'ratelimit.rules', array() ) )
				),
				'stopped' => isset( $counts['rate'] ) ? $counts['rate'] : 0,
			)
		);
	}

	/**
	 * Save the limits.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function update_item( $request ) {
		$settings = Options::all();

		if ( null !== $request->get_param( 'enabled' ) ) {
			$settings['firewall']['modules']['rate']['on'] = $this->bool( $request, 'enabled', true );
		}

		$preset = $request->get_param( 'preset' );
		if ( in_array( $preset, array( 'relaxed', 'balanced', 'strict' ), true ) ) {
			$settings['ratelimit']['preset'] = $preset;
			$settings['ratelimit']['rules']  = Options::preset_rules( $preset );
		}

		$action = $request->get_param( 'action' );
		if ( in_array( $action, array( 'throttle', 'block' ), true ) ) {
			$settings['ratelimit']['act'] = $action;
		}

		if ( null !== $request->get_param( 'bypass' ) ) {
			$settings['ratelimit']['bypass'] = $this->bool( $request, 'bypass', true );
		}

		$rules = $request->get_param( 'rules' );
		if ( is_array( $rules ) ) {
			$existing = array();
			foreach ( (array) $settings['ratelimit']['rules'] as $rule ) {
				$existing[ $rule['key'] ] = $rule;
			}

			$custom = false;

			foreach ( $rules as $patch ) {
				$key = isset( $patch['key'] ) ? sanitize_key( $patch['key'] ) : '';

				if ( ! isset( $existing[ $key ] ) ) {
					continue;
				}

				if ( array_key_exists( 'on', $patch ) ) {
					$existing[ $key ]['on'] = rest_sanitize_boolean( $patch['on'] );
				}

				if ( array_key_exists( 'limit', $patch ) ) {
					$limit = max( 0, (int) $patch['limit'] );

					if ( $limit !== (int) $existing[ $key ]['limit'] ) {
						$custom = true;
					}

					$existing[ $key ]['limit'] = $limit;
				}
			}

			$settings['ratelimit']['rules'] = array_values( $existing );

			if ( $custom && ! in_array( $preset, array( 'relaxed', 'balanced', 'strict' ), true ) ) {
				$settings['ratelimit']['preset'] = 'custom';
			}
		}

		Options::save( $settings );

		return $this->get_item( $request );
	}
}
