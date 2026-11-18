<?php
/**
 * Fixed-window hit counters.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Helpers;

defined( 'ABSPATH' ) || exit;

/**
 * Counts hits per key inside a fixed time window.
 *
 * The window opens with the first hit and closes a set time later, whatever
 * happens in between. Saving a plain count back with set_transient() on every
 * hit would push its expiry out each time, so a client that kept sending
 * requests would never see its count reset - and anyone retrying a "slow down"
 * page would stay blocked for as long as they kept retrying.
 */
class Counter {

	/**
	 * Count one hit and return the total for the current window.
	 *
	 * @param string $key    Transient key.
	 * @param int    $window Window length in seconds.
	 * @return int Hits in the current window, this one included.
	 */
	public static function hit( $key, $window ) {
		$now    = time();
		$window = max( 1, (int) $window );
		$entry  = get_transient( $key );

		if ( ! is_array( $entry ) || ! isset( $entry['start'], $entry['count'] ) || (int) $entry['start'] + $window <= $now ) {
			$entry = array(
				'start' => $now,
				'count' => 0,
			);
		}

		++$entry['count'];

		// Expire when the window closes, not a full window from now.
		set_transient( $key, $entry, max( 1, (int) $entry['start'] + $window - $now ) );

		return (int) $entry['count'];
	}
}
