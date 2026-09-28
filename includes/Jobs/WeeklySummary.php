<?php
/**
 * Scheduled weekly summary email.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Jobs;

use TekSecurity\Modules\Alerts;

defined( 'ABSPATH' ) || exit;

/**
 * Sends the Monday digest.
 */
class WeeklySummary extends Job {

	/**
	 * Job key.
	 *
	 * @return string
	 */
	public function key() {
		return 'weekly_summary';
	}

	/**
	 * Send the digest.
	 *
	 * @return array
	 */
	protected function handle() {
		$alerts = new Alerts();

		return array( 'sent' => (bool) $alerts->send_weekly_summary() );
	}
}
