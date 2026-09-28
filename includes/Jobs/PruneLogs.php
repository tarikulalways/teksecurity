<?php
/**
 * Scheduled traffic log cleanup.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Jobs;

use TekSecurity\Helpers\Logger;
use TekSecurity\Modules\Login;

defined( 'ABSPATH' ) || exit;

/**
 * Drops events past the retention window and expired lockouts.
 */
class PruneLogs extends Job {

	/**
	 * Job key.
	 *
	 * @return string
	 */
	public function key() {
		return 'prune_logs';
	}

	/**
	 * Delete stale rows.
	 *
	 * @return array
	 */
	protected function handle() {
		$removed = Logger::prune();
		Login::purge_expired();

		return array( 'removed' => $removed );
	}
}
