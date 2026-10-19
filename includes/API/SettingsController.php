<?php
/**
 * Alerts, data retention, onboarding and manual scans.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Core\Options;
use TekSecurity\Jobs\IntegrityScan;
use TekSecurity\Jobs\PruneLogs;
use TekSecurity\Jobs\VulnerabilityScan;
use TekSecurity\Modules\Integrity;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Routes for the Settings screen and the setup wizard.
 */
class SettingsController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/settings',
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
			'/onboarding',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'finish_onboarding' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/scan/(?P<job>integrity|vulnerability|prune)',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'run_scan' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/integrity',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_integrity' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);
	}

	/**
	 * Current settings.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_item( $request ) {
		unset( $request );

		return new WP_REST_Response(
			array(
				'mode'      => (string) Options::get( 'mode', 'simple' ),
				'onboarded' => (bool) Options::get( 'onboarded', false ),
				'alerts'    => array(
					'email'  => (string) Options::get( 'alerts.email', get_option( 'admin_email' ) ),
					'level'  => (string) Options::get( 'alerts.alerts', 'critical' ),
					'weekly' => (bool) Options::get( 'alerts.weekly', true ),
				),
				'data'      => array(
					'retention' => (string) Options::get( 'data.retention', '30' ),
					'proxy'     => (string) Options::get( 'data.proxy', 'direct' ),
				),
				'integrity' => Integrity::summary(),
				// So the Scans screen can say when the vulnerability check last
				// ran, the same way it does for the integrity check, instead of
				// leaving that one row with no history at all.
				'vulnerability' => self::vulnerability_summary(),
			)
		);
	}

	/**
	 * When the vulnerability scan last ran, and what it found.
	 *
	 * @return array
	 */
	protected static function vulnerability_summary() {
		$last = ( new VulnerabilityScan() )->last_result();

		return array(
			'enabled'    => (bool) Options::get( 'vulnerability.on', true ),
			'lastScanAt' => isset( $last['finishedAt'] ) ? (string) $last['finishedAt'] : null,
			'scanned'    => isset( $last['scanned'] ) ? (int) $last['scanned'] : 0,
			'findings'   => isset( $last['findings'] ) ? (int) $last['findings'] : 0,
			'error'      => isset( $last['error'] ) ? (string) $last['error'] : null,
		);
	}

	/**
	 * Save the settings.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function update_item( $request ) {
		$settings = Options::all();

		$mode = $request->get_param( 'mode' );
		if ( in_array( $mode, array( 'simple', 'advanced' ), true ) ) {
			$settings['mode'] = $mode;
		}

		$alerts = (array) $request->get_param( 'alerts' );

		if ( isset( $alerts['level'] ) && in_array( $alerts['level'], array( 'critical', 'all', 'off' ), true ) ) {
			$settings['alerts']['alerts'] = $alerts['level'];
		}

		if ( isset( $alerts['weekly'] ) ) {
			$settings['alerts']['weekly'] = rest_sanitize_boolean( $alerts['weekly'] );
		}

		if ( isset( $alerts['email'] ) ) {
			$email = sanitize_email( $alerts['email'] );
			$level = $settings['alerts']['alerts'];

			if ( 'off' !== $level && ! is_email( $email ) ) {
				return new WP_Error(
					'teksecurity_bad_email',
					__( 'Enter a valid email address, or choose Nothing below.', 'teksecurity' ),
					array( 'status' => 400 )
				);
			}

			$settings['alerts']['email'] = $email;
		}

		$data = (array) $request->get_param( 'data' );

		if ( isset( $data['retention'] ) ) {
			$settings['data']['retention'] = (string) absint( $data['retention'] );
		}

		if ( isset( $data['proxy'] ) && in_array( $data['proxy'], array( 'direct', 'cloudflare', 'proxy' ), true ) ) {
			$settings['data']['proxy'] = $data['proxy'];
		}

		Options::save( $settings );

		return $this->get_item( $request );
	}

	/**
	 * Store the wizard's answers and mark onboarding done.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function finish_onboarding( $request ) {
		$settings = Options::all();

		$mode = $request->get_param( 'mode' );
		if ( in_array( $mode, array( 'simple', 'advanced' ), true ) ) {
			$settings['mode'] = $mode;
		}

		$proxy = $request->get_param( 'proxy' );
		if ( in_array( $proxy, array( 'direct', 'cloudflare', 'proxy' ), true ) ) {
			$settings['data']['proxy'] = $proxy;
		}

		$level = $request->get_param( 'level' );
		if ( in_array( $level, array( 'protect', 'learning' ), true ) ) {
			$settings['firewall']['mode'] = $level;
		}

		$alerts = $request->get_param( 'alerts' );
		if ( in_array( $alerts, array( 'critical', 'all', 'off' ), true ) ) {
			$settings['alerts']['alerts'] = $alerts;
		}

		$email = sanitize_email( (string) $request->get_param( 'email' ) );
		if ( 'off' !== $settings['alerts']['alerts'] ) {
			if ( ! is_email( $email ) ) {
				return new WP_Error(
					'teksecurity_bad_email',
					__( 'Enter a valid email address, or choose Nothing.', 'teksecurity' ),
					array( 'status' => 400 )
				);
			}
			$settings['alerts']['email'] = $email;
		} elseif ( is_email( $email ) ) {
			$settings['alerts']['email'] = $email;
		}

		$settings['onboarded'] = true;

		Options::save( $settings );

		return $this->get_item( $request );
	}

	/**
	 * Run one job on demand.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function run_scan( $request ) {
		$jobs = array(
			'integrity'     => IntegrityScan::class,
			'vulnerability' => VulnerabilityScan::class,
			'prune'         => PruneLogs::class,
		);

		$key   = (string) $request->get_param( 'job' );
		$class = $jobs[ $key ];
		$job   = new $class();

		$result = $job->run();

		return new WP_REST_Response(
			array(
				'job'     => $key,
				'running' => null === $result,
				'result'  => null === $result ? $job->last_result() : $result,
			)
		);
	}

	/**
	 * The integrity findings.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_integrity( $request ) {
		unset( $request );

		return new WP_REST_Response(
			array(
				'summary' => Integrity::summary(),
				'issues'  => Integrity::issues(),
			)
		);
	}
}
