<?php
/**
 * Scheduled core file integrity scan.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Jobs;

use TekSecurity\Core\Options;
use TekSecurity\Modules\Integrity;

defined( 'ABSPATH' ) || exit;

/**
 * Runs Integrity::scan() daily.
 */
class IntegrityScan extends Job {

	/**
	 * Job key.
	 *
	 * @return string
	 */
	public function key() {
		return 'integrity_scan';
	}

	/**
	 * Compare core files against the published checksums.
	 *
	 * @return array
	 */
	protected function handle() {
		if ( ! Options::get( 'integrity.on', true ) ) {
			return array( 'skipped' => true );
		}

		return Integrity::scan();
	}
}
