<?php
/**
 * Admin menu and asset loading for the React app.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Core;

use TekSecurity\API\OverviewController;
use TekSecurity\Helpers\Rules;
use TekSecurity\Modules\Login;
use TekSecurity\Modules\Vulnerability;

defined( 'ABSPATH' ) || exit;

/**
 * Mounts the single-page admin under its own top-level menu.
 */
class Admin {

	const SLUG   = 'teksecurity';
	const HANDLE = 'teksecurity-admin';

	/**
	 * Hook in.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_filter( 'plugin_action_links_' . TEKSEC_BASENAME, array( $this, 'action_links' ) );
	}

	/**
	 * The screens the React router knows about, in sidebar order.
	 *
	 * @return array
	 */
	public static function pages() {
		return array(
			array( 'overview', __( 'Dashboard', 'teksecurity' ), 'ph-squares-four' ),
			array( 'firewall', __( 'Firewall', 'teksecurity' ), 'ph-wall' ),
			array( 'traffic', __( 'Traffic log', 'teksecurity' ), 'ph-pulse' ),
			array( 'login', __( 'Login protection', 'teksecurity' ), 'ph-password' ),
			array( 'twofa', __( 'Two-factor auth', 'teksecurity' ), 'ph-device-mobile' ),
			array( 'ratelimit', __( 'Rate limiting', 'teksecurity' ), 'ph-gauge' ),
			array( 'uploads', __( 'File uploads', 'teksecurity' ), 'ph-upload-simple' ),
			array( 'plugins', __( 'Plugin shields', 'teksecurity' ), 'ph-plug' ),
			array( 'ips', __( 'IP lists', 'teksecurity' ), 'ph-prohibit' ),
			array( 'settings', __( 'Settings', 'teksecurity' ), 'ph-gear' ),
		);
	}

	/**
	 * Register the menu and its submenu items.
	 *
	 * @return void
	 */
	public function add_menu() {
		$badge = OverviewController::two_factor_missing() + count( Vulnerability::exposed() );
		$title = __( 'TekSecurity', 'teksecurity' );

		if ( $badge > 0 ) {
			$title .= sprintf(
				' <span class="awaiting-mod"><span class="pending-count">%d</span></span>',
				$badge
			);
		}

		add_menu_page(
			__( 'TekSecurity', 'teksecurity' ),
			$title,
			'manage_options',
			self::SLUG,
			array( $this, 'render' ),
			'dashicons-shield-alt',
			58
		);

		foreach ( self::pages() as $page ) {
			list( $key, $label ) = $page;

			add_submenu_page(
				self::SLUG,
				$label,
				$label,
				'manage_options',
				'overview' === $key ? self::SLUG : self::SLUG . '#/' . $key,
				array( $this, 'render' )
			);
		}
	}

	/**
	 * The mount point. Everything else is React.
	 *
	 * @return void
	 */
	public function render() {
		$this->print_icon_sprite();

		echo '<div id="teksecurity-root"></div>';
	}

	/**
	 * Inline the icon sprite the app draws from.
	 *
	 * The icons ship with the plugin rather than coming from a CDN, so the
	 * admin makes no third-party request and works on a site with no outbound
	 * network access at all.
	 *
	 * @return void
	 */
	protected function print_icon_sprite() {
		$path = TEKSEC_PATH . 'assets/icons.svg';

		if ( ! is_readable( $path ) ) {
			return;
		}

		$sprite = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		echo wp_kses(
			$sprite,
			array(
				'svg'      => array(
					'xmlns'       => true,
					'style'       => true,
					'aria-hidden' => true,
				),
				'symbol'   => array(
					'id'      => true,
					'viewbox' => true,
				),
				'path'     => array(
					'd'    => true,
					'fill' => true,
				),
				'circle'   => array(
					'cx'   => true,
					'cy'   => true,
					'r'    => true,
					'fill' => true,
				),
				'rect'     => array(
					'x'      => true,
					'y'      => true,
					'width'  => true,
					'height' => true,
					'rx'     => true,
					'fill'   => true,
				),
				'line'     => array(
					'x1' => true,
					'y1' => true,
					'x2' => true,
					'y2' => true,
				),
				'polyline' => array( 'points' => true ),
				'polygon'  => array( 'points' => true ),
				'g'        => array( 'fill' => true ),
			)
		);
	}

	/**
	 * Load the built bundle on our screen only.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue( $hook ) {
		if ( false === strpos( (string) $hook, self::SLUG ) ) {
			return;
		}

		$asset_file = TEKSEC_PATH . 'build/index.asset.php';

		if ( ! file_exists( $asset_file ) ) {
			add_action( 'admin_notices', array( $this, 'build_notice' ) );
			return;
		}

		$asset = require $asset_file;

		wp_enqueue_script(
			self::HANDLE,
			TEKSEC_URL . 'build/index.js',
			$asset['dependencies'],
			$asset['version'],
			true
		);

		if ( file_exists( TEKSEC_PATH . 'build/index.css' ) ) {
			wp_enqueue_style(
				self::HANDLE,
				TEKSEC_URL . 'build/index.css',
				array( 'wp-components' ),
				$asset['version']
			);
		}

		wp_set_script_translations( self::HANDLE, 'teksecurity', TEKSEC_PATH . 'languages' );

		wp_localize_script( self::HANDLE, 'tekSecurityData', $this->boot_data() );
	}

	/**
	 * Data the app needs before its first request.
	 *
	 * @return array
	 */
	protected function boot_data() {
		$user  = wp_get_current_user();
		$types = array();

		foreach ( Rules::types() as $key => $type ) {
			$types[ $key ] = array(
				'label'   => $type['label'],
				'explain' => $type['explain'],
			);
		}

		return array(
			'root'      => esc_url_raw( rest_url( 'teksecurity/v1' ) ),
			'nonce'     => wp_create_nonce( 'wp_rest' ),
			'adminUrl'  => admin_url( 'admin.php?page=' . self::SLUG ),
			'siteName'  => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			'siteHost'  => wp_parse_url( home_url(), PHP_URL_HOST ),
			'pages'     => array_map(
				static function ( $page ) {
					return array(
						'key'   => $page[0],
						'label' => $page[1],
						'icon'  => $page[2],
					);
				},
				self::pages()
			),
			'types'     => $types,
			'mode'      => (string) Options::get( 'mode', 'simple' ),
			'onboarded' => (bool) Options::get( 'onboarded', false ),
			'badges'    => array(
				'twofa'   => OverviewController::two_factor_missing(),
				'plugins' => count( Vulnerability::exposed() ),
				'login'   => count( Login::lockouts() ),
			),
			'user'      => array(
				'id'    => $user->ID,
				'name'  => $user->display_name,
				'email' => $user->user_email,
			),
			'version'   => TEKSEC_VERSION,
		);
	}

	/**
	 * Tell the developer the bundle has not been built.
	 *
	 * @return void
	 */
	public function build_notice() {
		printf(
			'<div class="notice notice-error"><p>%s</p></div>',
			esc_html__( 'TekSecurity: the admin bundle is missing. Run "npm install && npm run build" in the plugin folder.', 'teksecurity' )
		);
	}

	/**
	 * Add a Settings link on the Plugins screen.
	 *
	 * @param array $links Existing links.
	 * @return array
	 */
	public function action_links( $links ) {
		array_unshift(
			$links,
			sprintf(
				'<a href="%s">%s</a>',
				esc_url( admin_url( 'admin.php?page=' . self::SLUG ) ),
				esc_html__( 'Dashboard', 'teksecurity' )
			)
		);

		return $links;
	}
}
