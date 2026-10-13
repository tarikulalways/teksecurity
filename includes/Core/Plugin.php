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
	 * Strings that may be printed before translations are available.
	 *
	 * The firewall ends a blocked request long before WordPress reaches `init`,
	 * so these cannot go through a gettext call at the point of use. They are
	 * listed here, as plain literals, so translators still see them and so the
	 * lookup happens only once `init` has run.
	 *
	 * @return array English text => translated text.
	 */
	protected static function early_strings() {
		return array(
			'This request was blocked by the site firewall. If you think this is a mistake, contact the site owner.' => __( 'This request was blocked by the site firewall. If you think this is a mistake, contact the site owner.', 'teksecurity' ),
			'This request was blocked by a TekSecurity virtual patch.' => __( 'This request was blocked by a TekSecurity virtual patch.', 'teksecurity' ),
			'Too many requests from your address. Please wait a moment and try again.' => __( 'Too many requests from your address. Please wait a moment and try again.', 'teksecurity' ),
			'Request blocked' => __( 'Request blocked', 'teksecurity' ),
			'Slow down'       => __( 'Slow down', 'teksecurity' ),
		);
	}

	/**
	 * Translate a string that may be needed before `init`.
	 *
	 * Before `init` the text stays in English, because WordPress warns about
	 * loading a textdomain that early. Once `init` has run the string is looked
	 * up in the table above. A site that needs its own wording either way can
	 * supply it through the filter.
	 *
	 * @param string $text    English text.
	 * @param string $context Where the string is used, e.g. "block_message".
	 * @return string
	 */
	public static function early_text( $text, $context = '' ) {
		$translated = (string) $text;

		if ( did_action( 'init' ) ) {
			$strings = self::early_strings();

			if ( isset( $strings[ $text ] ) ) {
				$translated = $strings[ $text ];
			}
		}

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
