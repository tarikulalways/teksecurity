<?php
/**
 * Plugin bootstrap.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Core;

use TekSecurity\Jobs\Scheduler;
use TekSecurity\Modules\Alerts;
use TekSecurity\Modules\Firewall;
use TekSecurity\Modules\Hardening;
use TekSecurity\Modules\Integrity;
use TekSecurity\Modules\Login;
use TekSecurity\Modules\TwoFactor;
use TekSecurity\Modules\TwoFactorScreen;
use TekSecurity\Modules\Vulnerability;

defined( 'ABSPATH' ) || exit;

/**
 * Wires every module, controller and job together.
 */
final class Plugin {

	/**
	 * Singleton instance.
	 *
	 * @var Plugin|null
	 */
	protected static $instance = null;

	/**
	 * Booted services, keyed by short name.
	 *
	 * @var array
	 */
	protected $services = array();

	/**
	 * Whether boot() already ran.
	 *
	 * @var bool
	 */
	protected $booted = false;

	/**
	 * Get the instance.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Private constructor: use instance().
	 */
	private function __construct() {}

	/**
	 * Start the plugin.
	 *
	 * @return void
	 */
	public function boot() {
		if ( $this->booted ) {
			return;
		}

		$this->booted = true;

		add_action( 'init', array( $this, 'load_textdomain' ) );
		add_action( 'admin_init', array( 'TekSecurity\\Core\\Installer', 'maybe_upgrade' ) );

		$this->services = array(
			'firewall'      => new Firewall(),
			'hardening'     => new Hardening(),
			'login'         => new Login(),
			'twofactor'     => new TwoFactor(),
			'twofactorscreen' => new TwoFactorScreen(),
			'vulnerability' => new Vulnerability(),
			'integrity'     => new Integrity(),
			'alerts'        => new Alerts(),
			'scheduler'     => new Scheduler(),
			'rest'          => new Rest(),
			'admin'         => new Admin(),
		);

		foreach ( $this->services as $service ) {
			$service->register();
		}

		/**
		 * Fires once every TekSecurity service is registered.
		 *
		 * @param Plugin $plugin The plugin instance.
		 */
		do_action( 'teksecurity_loaded', $this );
	}

	/**
	 * Fetch a booted service.
	 *
	 * @param string $key Service key.
	 * @return object|null
	 */
	public function service( $key ) {
		return isset( $this->services[ $key ] ) ? $this->services[ $key ] : null;
	}

	/**
	 * Load translations.
	 *
	 * @return void
	 */
	public function load_textdomain() {
		// Kept deliberately: WordPress only auto-loads translations for plugins
		// it serves itself, and this one also ships outside that directory.
		// phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound
		load_plugin_textdomain( 'teksecurity', false, dirname( TEKSEC_BASENAME ) . '/languages' );
	}

	/**
	 * Translate a string that may be needed before `init`.
	 *
	 * The firewall ends a blocked request long before WordPress reaches `init`,
	 * and WordPress warns about loading a textdomain that early. So the few
	 * strings on a block page stay in English when the request is cut short,
	 * and are translated normally once `init` has run. A site that needs those
	 * words in its own language can supply them through the filter.
	 *
	 * @param string $text    English text.
	 * @param string $context Where the string is used, e.g. "block_message".
	 * @return string
	 */
	public static function early_text( $text, $context = '' ) {
		$translated = did_action( 'init' ) ? __( $text, 'teksecurity' ) : $text; // phpcs:ignore WordPress.WP.I18n

		/**
		 * Filter a string shown on a blocked request.
		 *
		 * The firewall runs before WordPress can load translations, so these
		 * strings default to English. Return your own wording here.
		 *
		 * @param string $translated The text as it will be shown.
		 * @param string $context    Where the string is used.
		 */
		return apply_filters( 'teksecurity_early_text', $translated, $context );
	}
}
