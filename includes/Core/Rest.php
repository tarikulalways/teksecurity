<?php
/**
 * REST route registration.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Core;

use TekSecurity\API\FirewallController;
use TekSecurity\API\IpsController;
use TekSecurity\API\LoginController;
use TekSecurity\API\OverviewController;
use TekSecurity\API\PluginsController;
use TekSecurity\API\RateLimitController;
use TekSecurity\API\SettingsController;
use TekSecurity\API\TrafficController;
use TekSecurity\API\TwoFactorController;
use TekSecurity\API\UploadsController;

defined( 'ABSPATH' ) || exit;

/**
 * Boots every controller on rest_api_init.
 */
class Rest {

	/**
	 * Controller classes.
	 *
	 * @return array
	 */
	public static function controllers() {
		return array(
			OverviewController::class,
			FirewallController::class,
			TrafficController::class,
			LoginController::class,
			TwoFactorController::class,
			RateLimitController::class,
			UploadsController::class,
			PluginsController::class,
			IpsController::class,
			SettingsController::class,
		);
	}

	/**
	 * Hook in.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register every route.
	 *
	 * @return void
	 */
	public function register_routes() {
		foreach ( self::controllers() as $class ) {
			$controller = new $class();
			$controller->register_routes();
		}
	}
}
