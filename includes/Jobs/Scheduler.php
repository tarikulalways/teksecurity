<?php
/**
 * Cron registration for the background jobs.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Jobs;

use TekSecurity\Core\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Owns every wp-cron hook the plugin uses.
 */
class Scheduler {

	/**
	 * Hook => recurrence.
	 *
	 * @return array
	 */
	public static function events() {
		return array(
			'teksecurity_integrity_scan'     => 'daily',
			'teksecurity_vulnerability_scan' => 'twicedaily',
			'teksecurity_prune_logs'         => 'daily',
			'teksecurity_weekly_summary'     => 'weekly',
		);
	}

	/**
	 * Bind the job callbacks.
	 *
	 * @return void
	 */
	public function register() {
		add_filter( 'cron_schedules', array( $this, 'add_weekly' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected

		add_action( 'teksecurity_integrity_scan', array( new IntegrityScan(), 'run' ) );
		add_action( 'teksecurity_vulnerability_scan', array( new VulnerabilityScan(), 'run' ) );
		add_action( 'teksecurity_prune_logs', array( new PruneLogs(), 'run' ) );
		add_action( 'teksecurity_weekly_summary', array( new WeeklySummary(), 'run' ) );

		add_action( 'init', array( __CLASS__, 'schedule' ) );
	}

	/**
	 * Add the weekly recurrence WordPress does not ship.
	 *
	 * @param array $schedules Existing schedules.
	 * @return array
	 */
	public function add_weekly( $schedules ) {
		if ( ! isset( $schedules['weekly'] ) ) {
			$schedules['weekly'] = array(
				'interval' => WEEK_IN_SECONDS,
				'display'  => __( 'Once weekly', 'teksecurity' ),
			);
		}

		return $schedules;
	}

	/**
	 * Setting that switches a job's feature on, for the jobs that have one.
	 *
	 * @return array Hook => dotted settings path.
	 */
	protected static function switches() {
		return array(
			'teksecurity_integrity_scan'     => 'integrity.on',
			'teksecurity_vulnerability_scan' => 'vulnerability.on',
		);
	}

	/**
	 * Whether a job's feature is switched on.
	 *
	 * @param string $hook Cron hook.
	 * @return bool
	 */
	protected static function is_enabled( $hook ) {
		$switches = self::switches();

		return ! isset( $switches[ $hook ] ) || (bool) Options::get( $switches[ $hook ], false );
	}

	/**
	 * Put every job whose feature is on on the schedule, and take the others off.
	 *
	 * A job that is switched off is not scheduled at all, rather than scheduled
	 * and skipped: the integrity scan contacts WordPress.org, so it must not be
	 * queued until the owner has turned it on.
	 *
	 * @return void
	 */
	public static function schedule() {
		foreach ( self::events() as $hook => $recurrence ) {
			$next = wp_next_scheduled( $hook );

			if ( ! self::is_enabled( $hook ) ) {
				if ( $next ) {
					wp_clear_scheduled_hook( $hook );
				}
				continue;
			}

			if ( ! $next ) {
				wp_schedule_event( time() + wp_rand( 60, 600 ), $recurrence, $hook );
			}
		}
	}

	/**
	 * Clear every job.
	 *
	 * @return void
	 */
	public static function unschedule() {
		foreach ( array_keys( self::events() ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}
}
