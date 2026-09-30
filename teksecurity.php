<?php
/**
 * Plugin Name:       TekSecurity – Firewall, Login Security, Two-Factor Authentication & Malware Scan
 * Plugin URI:        https://teksecurity.io/
 * Description:       Firewall, login protection, two-factor authentication, plugin vulnerability shields and file integrity monitoring for WordPress.
 * Version:           1.0.0
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            TekSecurity
 * Author URI:        https://teksecurity.io/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       teksecurity
 * Domain Path:       /languages
 *
 * @package TekSecurity
 */

defined( 'ABSPATH' ) || exit;

define( 'TEKSEC_VERSION', '1.0.0' );
define( 'TEKSEC_DB_VERSION', '1' );
define( 'TEKSEC_FILE', __FILE__ );
define( 'TEKSEC_PATH', plugin_dir_path( __FILE__ ) );
define( 'TEKSEC_URL', plugin_dir_url( __FILE__ ) );
define( 'TEKSEC_BASENAME', plugin_basename( __FILE__ ) );

require_once TEKSEC_PATH . 'includes/Core/Autoloader.php';

TekSecurity\Core\Autoloader::register();

register_activation_hook( __FILE__, array( 'TekSecurity\\Core\\Installer', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'TekSecurity\\Core\\Installer', 'deactivate' ) );

/**
 * Main plugin instance.
 *
 * @return TekSecurity\Core\Plugin
 */
function teksecurity() {
	return TekSecurity\Core\Plugin::instance();
}

teksecurity()->boot();
