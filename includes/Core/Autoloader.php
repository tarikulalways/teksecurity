<?php
/**
 * PSR-4 style autoloader for the TekSecurity namespace.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Maps TekSecurity\Foo\Bar to includes/Foo/Bar.php.
 */
class Autoloader {

	/**
	 * Register the autoloader.
	 *
	 * @return void
	 */
	public static function register() {
		spl_autoload_register( array( __CLASS__, 'load' ) );
	}

	/**
	 * Load a class file.
	 *
	 * @param string $class_name Fully qualified class name.
	 * @return void
	 */
	public static function load( $class_name ) {
		if ( 0 !== strpos( $class_name, 'TekSecurity\\' ) ) {
			return;
		}

		$relative = substr( $class_name, strlen( 'TekSecurity\\' ) );
		$path     = TEKSEC_PATH . 'includes/' . str_replace( '\\', '/', $relative ) . '.php';

		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}
}
