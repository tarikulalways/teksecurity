<?php
/**
 * File upload protection settings.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Core\Options;
use TekSecurity\Helpers\Logger;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Routes for the File uploads screen.
 */
class UploadsController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/uploads',
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
			'/uploads/extensions',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'add_extension' ),
					'permission_callback' => array( $this, 'permission' ),
					'args'                => array(
						'ext' => array(
							'type'     => 'string',
							'required' => true,
						),
					),
				),
				array(
					'methods'             => 'DELETE',
					'callback'            => array( $this, 'remove_extension' ),
					'permission_callback' => array( $this, 'permission' ),
					'args'                => array(
						'ext' => array(
							'type'     => 'string',
							'required' => true,
						),
					),
				),
			)
		);
	}

	/**
	 * Current upload rules and the recent rejections.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_item( $request ) {
		unset( $request );

		$recent = Logger::query(
			array(
				'type'     => 'upload',
				'per_page' => 6,
			)
		);

		$counts = Logger::counts_by_type( 7 );

		return new WP_REST_Response(
			array(
				'enabled'    => (bool) Options::get( 'firewall.modules.upload.on', true ),
				'extensions' => array_values( (array) Options::get( 'uploads.exts', array() ) ),
				'scan'       => (bool) Options::get( 'uploads.scan', true ),
				'svg'        => (bool) Options::get( 'uploads.svg', true ),
				'guests'     => (bool) Options::get( 'uploads.guests', true ),
				'recent'     => $recent['rows'],
				'stopped'    => isset( $counts['upload'] ) ? $counts['upload'] : 0,
			)
		);
	}

	/**
	 * Save the toggles.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function update_item( $request ) {
		$settings = Options::all();

		if ( null !== $request->get_param( 'enabled' ) ) {
			$settings['firewall']['modules']['upload']['on'] = $this->bool( $request, 'enabled', true );
		}

		foreach ( array( 'scan', 'svg', 'guests' ) as $key ) {
			if ( null !== $request->get_param( $key ) ) {
				$settings['uploads'][ $key ] = $this->bool( $request, $key, true );
			}
		}

		Options::save( $settings );

		return $this->get_item( $request );
	}

	/**
	 * Block another extension.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function add_extension( $request ) {
		$ext = strtolower( ltrim( trim( (string) $request->get_param( 'ext' ) ), '.' ) );

		if ( ! preg_match( '/^[a-z0-9]{1,10}$/', $ext ) ) {
			return new WP_Error(
				'teksecurity_bad_extension',
				__( 'Use letters and numbers only, e.g. pht.', 'teksecurity' ),
				array( 'status' => 400 )
			);
		}

		$exts = (array) Options::get( 'uploads.exts', array() );

		if ( in_array( $ext, $exts, true ) ) {
			return new WP_Error(
				'teksecurity_duplicate_extension',
				sprintf(
					/* translators: %s: file extension. */
					__( '.%s is already blocked.', 'teksecurity' ),
					$ext
				),
				array( 'status' => 409 )
			);
		}

		$exts[] = $ext;
		Options::set( 'uploads.exts', array_values( $exts ) );

		return $this->get_item( $request );
	}

	/**
	 * Stop blocking an extension.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function remove_extension( $request ) {
		$ext  = strtolower( ltrim( trim( (string) $request->get_param( 'ext' ) ), '.' ) );
		$exts = array_values(
			array_filter(
				(array) Options::get( 'uploads.exts', array() ),
				static function ( $item ) use ( $ext ) {
					return $item !== $ext;
				}
			)
		);

		Options::set( 'uploads.exts', $exts );

		return $this->get_item( $request );
	}
}
