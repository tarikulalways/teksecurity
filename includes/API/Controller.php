<?php
/**
 * Shared behaviour for the REST controllers.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use WP_REST_Controller;

defined( 'ABSPATH' ) || exit;

/**
 * Every TekSecurity route lives under teksecurity/v1 and needs manage_options.
 */
abstract class Controller extends WP_REST_Controller {

	/**
	 * Route namespace.
	 *
	 * @var string
	 */
	protected $namespace = 'teksecurity/v1';

	/**
	 * Only administrators may read or change security settings.
	 *
	 * @return bool
	 */
	public function permission() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Permission check for the endpoints a user may call for their own account.
	 *
	 * @return bool
	 */
	public function self_permission() {
		return is_user_logged_in();
	}

	/**
	 * Read a boolean request parameter.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @param string           $key     Parameter name.
	 * @param bool             $default Fallback.
	 * @return bool
	 */
	protected function bool( $request, $key, $default = false ) {
		$value = $request->get_param( $key );

		return null === $value ? $default : rest_sanitize_boolean( $value );
	}
}
