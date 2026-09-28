<?php
/**
 * Shared behaviour for background jobs.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Jobs;

defined( 'ABSPATH' ) || exit;

/**
 * Keeps two runs of the same job from overlapping and records the last result.
 */
abstract class Job {

	/**
	 * Unique job key, used for the lock and the stored result.
	 *
	 * @return string
	 */
	abstract public function key();

	/**
	 * Do the work.
	 *
	 * @return array Result payload.
	 */
	abstract protected function handle();

	/**
	 * Run the job behind a lock.
	 *
	 * @return array|null Result, or null when another run holds the lock.
	 */
	public function run() {
		$lock = 'teksecurity_job_' . $this->key();

		if ( get_transient( $lock ) ) {
			return null;
		}

		set_transient( $lock, time(), 15 * MINUTE_IN_SECONDS );

		try {
			$result = $this->handle();
		} catch ( \Throwable $e ) {
			$result = array( 'error' => $e->getMessage() );
		}

		delete_transient( $lock );

		$result['finishedAt'] = gmdate( 'c' );
		update_option( 'teksecurity_job_' . $this->key(), $result, false );

		return $result;
	}

	/**
	 * The stored result of the last run.
	 *
	 * @return array
	 */
	public function last_result() {
		return (array) get_option( 'teksecurity_job_' . $this->key(), array() );
	}
}
