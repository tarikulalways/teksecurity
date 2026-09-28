<?php
/**
 * Dashboard data.
 *
 * @package TekSecurity
 */

namespace TekSecurity\API;

use TekSecurity\Core\Options;
use TekSecurity\Helpers\IpList;
use TekSecurity\Helpers\Logger;
use TekSecurity\Helpers\Rules;
use TekSecurity\Modules\Integrity;
use TekSecurity\Modules\Login;
use TekSecurity\Modules\TwoFactor;
use TekSecurity\Modules\Vulnerability;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Everything the dashboard screen needs, in one request.
 */
class OverviewController extends Controller {

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			$this->namespace,
			'/overview',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_item' ),
					'permission_callback' => array( $this, 'permission' ),
				),
			)
		);
	}

	/**
	 * Build the dashboard payload.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function get_item( $request ) {
		unset( $request );

		$summary  = Logger::summary();
		$counts   = Logger::counts_by_type( 7 );
		$exposed  = Vulnerability::exposed();
		$statuses = self::module_statuses();

		$running = count(
			array_filter(
				$statuses,
				static function ( $row ) {
					return 'ok' === $row['tone'];
				}
			)
		);

		$blocklist = wp_list_pluck( IpList::all( 'block' ), 'ip' );
		$recent    = Logger::query(
			array(
				'per_page' => 7,
				'page'     => 0,
			)
		);

		$types     = Rules::types();
		$breakdown = array();

		arsort( $counts );
		foreach ( $counts as $type => $total ) {
			$breakdown[] = array(
				'type'  => $type,
				'label' => isset( $types[ $type ] ) ? $types[ $type ]['label'] : $type,
				'total' => $total,
			);
		}

		return new WP_REST_Response(
			array(
				'summary'    => array(
					'blockedToday'     => $summary['blocked_today'],
					'blockedYesterday' => $summary['blocked_yesterday'],
					'blockedWeek'      => $summary['blocked_week'],
					'loggedWeek'       => $summary['logged_week'],
					'uniqueIps'        => $summary['unique_ips'],
					'lastBlockedAt'    => $summary['last_blocked_at'],
					'blocklistedIps'   => count( $blocklist ),
					'modulesRunning'   => $running,
					'modulesTotal'     => count( $statuses ),
				),
				'byDay'      => Logger::blocked_by_day( 7 ),
				'breakdown'  => $breakdown,
				'recent'     => $recent['rows'],
				'modules'    => $statuses,
				'firewall'   => array(
					'mode' => Options::get( 'firewall.mode', 'protect' ),
				),
				'exposed'    => array_map(
					static function ( $row ) {
						return array(
							'slug' => $row['slug'],
							'name' => $row['name'],
						);
					},
					$exposed
				),
				'twofactor'  => array(
					'enabled'     => TwoFactor::enabled(),
					'notSetUp'    => self::two_factor_missing(),
				),
				'lockouts'   => count( Login::lockouts() ),
				'integrity'  => Integrity::summary(),
			)
		);
	}

	/**
	 * How many required users still have not set two-factor up.
	 *
	 * @return int
	 */
	public static function two_factor_missing() {
		if ( ! TwoFactor::enabled() ) {
			return 0;
		}

		return count(
			array_filter(
				TwoFactor::required_users(),
				static function ( $user ) {
					return 'none' === $user['status'];
				}
			)
		);
	}

	/**
	 * Status for each of the ten protections.
	 *
	 * @return array
	 */
	public static function module_statuses() {
		$mode      = Options::get( 'firewall.mode', 'protect' );
		$waf_keys  = array( 'malicious', 'exploit', 'sqli', 'xss', 'auth', 'priv' );
		$out       = array();

		foreach ( Rules::modules() as $module ) {
			$key      = $module['key'];
			$settings = (array) Options::get( 'firewall.modules.' . $key, array( 'on' => true ) );
			$is_waf   = in_array( $key, $waf_keys, true );

			if ( empty( $settings['on'] ) || ( $is_waf && 'off' === $mode ) ) {
				$label = __( 'Off', 'teksecurity' );
				$tone  = 'bad';
			} elseif ( $is_waf && 'learning' === $mode ) {
				$label = __( 'Learning', 'teksecurity' );
				$tone  = 'warn';
			} elseif ( $is_waf && 'log' === ( $settings['act'] ?? 'block' ) ) {
				$label = __( 'Log only', 'teksecurity' );
				$tone  = 'warn';
			} else {
				$label = __( 'Active', 'teksecurity' );
				$tone  = 'ok';
			}

			$out[] = array(
				'key'    => $key,
				'name'   => $module['name'],
				'icon'   => $module['icon'],
				'page'   => $module['page'],
				'desc'   => isset( $module['desc'] ) ? $module['desc'] : '',
				'rules'  => Rules::count( $key ),
				'on'     => ! empty( $settings['on'] ),
				'action' => isset( $settings['act'] ) ? $settings['act'] : null,
				'status' => $label,
				'tone'   => $tone,
			);
		}

		return $out;
	}
}
