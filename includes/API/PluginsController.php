<?php
/**
 * Plugin vulnerability shields.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Core\Options;
use TekSecurity\Jobs\VulnerabilityScan;
use TekSecurity\Modules\Vulnerability;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Routes for the Plugin shields screen.
 */
class PluginsController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/plugins',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_items' ),
					'permission_callback' => array( $this, 'permission' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'update_module' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/plugins/(?P<slug>[\w\-\.]+)/shield',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'set_shield' ),
					'permission_callback' => array( $this, 'permission' ),
					'args'                => array(
						'shield' => array(
							'type'     => 'boolean',
							'required' => true,
						),
					),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/plugins/(?P<slug>[\w\-\.]+)/update',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'update_plugin' ),
					'permission_callback' => array( $this, 'update_permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/plugins/rescan',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'rescan' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);
	}

	/**
	 * Installing an update needs the stronger capability.
	 *
	 * @return bool
	 */
	public function update_permission() {
		return current_user_can( 'update_plugins' );
	}

	/**
	 * Installed plugins with their vulnerability state.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_items( $request ) {
		unset( $request );

		$plugins = Vulnerability::plugins();

		return new WP_REST_Response(
			array(
				'enabled'    => (bool) Options::get( 'firewall.modules.plugin.on', true ),
				'plugins'    => $plugins,
				'vulnerable' => count(
					array_filter(
						$plugins,
						static function ( $row ) {
							return $row['vulnerable'];
						}
					)
				),
				'exposed'    => count( Vulnerability::exposed() ),
				'lastScan'   => ( new VulnerabilityScan() )->last_result(),
			)
		);
	}

	/**
	 * Turn the whole shield module on or off.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function update_module( $request ) {
		if ( null !== $request->get_param( 'enabled' ) ) {
			Options::set( 'firewall.modules.plugin.on', $this->bool( $request, 'enabled', true ) );
		}

		return $this->get_items( $request );
	}

	/**
	 * Turn one plugin's shield on or off.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function set_shield( $request ) {
		Vulnerability::set_shield(
			sanitize_key( $request->get_param( 'slug' ) ),
			$this->bool( $request, 'shield', true )
		);

		return $this->get_items( $request );
	}

	/**
	 * Install the fixed version of a plugin.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function update_plugin( $request ) {
		$slug = sanitize_key( $request->get_param( 'slug' ) );
		$file = '';

		foreach ( Vulnerability::plugins() as $plugin ) {
			if ( $plugin['slug'] === $slug ) {
				$file = $plugin['file'];
				break;
			}
		}

		if ( '' === $file ) {
			return new WP_Error(
				'teksecurity_plugin_not_found',
				__( 'That plugin is not installed on this site.', 'teksecurity' ),
				array( 'status' => 404 )
			);
		}

		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		wp_update_plugins();

		$upgrader = new \Plugin_Upgrader( new \WP_Ajax_Upgrader_Skin() );
		$result   = $upgrader->upgrade( $file );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		if ( false === $result ) {
			return new WP_Error(
				'teksecurity_update_failed',
				__( 'The update could not be installed. Try updating from the Plugins screen.', 'teksecurity' ),
				array( 'status' => 500 )
			);
		}

		( new VulnerabilityScan() )->run();

		return $this->get_items( $request );
	}

	/**
	 * Re-run the vulnerability scan now.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function rescan( $request ) {
		( new VulnerabilityScan() )->run();

		return $this->get_items( $request );
	}
}
