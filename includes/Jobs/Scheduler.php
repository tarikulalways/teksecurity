<?php
/**
 * Cron registration for the background jobs.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Jobs;

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
	 * Make sure every job is on the schedule.
	 *
	 * @return void
	 */
	public static function schedule() {
		foreach ( self::events() as $hook => $recurrence ) {
			if ( ! wp_next_scheduled( $hook ) ) {
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
