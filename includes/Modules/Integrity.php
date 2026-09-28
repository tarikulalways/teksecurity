<?php
/**
 * File integrity monitoring for WordPress core.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Modules;

use TekSecurity\Core\Installer;
use TekSecurity\Core\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Compares core files against the checksums WordPress.org publishes for the
 * installed version, and flags anything added, changed or missing.
 */
class Integrity {

	const LAST_SCAN_OPTION = 'teksecurity_integrity_last_scan';

	/**
	 * Files that legitimately differ from a stock install.
	 *
	 * @return array
	 */
	protected static function ignored() {
		/**
		 * Filter the core files the integrity scan skips.
		 *
		 * @param array $files Relative paths.
		 */
		return apply_filters(
			'teksecurity_integrity_ignored',
			array( 'wp-config-sample.php', 'wp-includes/version.php', 'readme.html', 'license.txt' )
		);
	}

	/**
	 * Hook in. Integrity runs from cron, so there is nothing on the request path.
	 *
	 * @return void
	 */
	public function register() {}

	/**
	 * Whether a checksum path belongs to WordPress core.
	 *
	 * The published checksums also cover the bundled themes under wp-content,
	 * but a site is free to delete those, and flagging a theme somebody removed
	 * on purpose as tampering would bury the findings that matter. Core is
	 * wp-admin, wp-includes and the PHP files in the root.
	 *
	 * @param string $file Relative path from the checksum list.
	 * @return bool
	 */
	protected static function is_core_path( $file ) {
		$is_core = 0 === strpos( $file, 'wp-admin/' )
			|| 0 === strpos( $file, WPINC . '/' )
			|| ( false === strpos( $file, '/' ) && '.php' === substr( $file, -4 ) );

		/**
		 * Filter whether a file from the core checksum list is compared.
		 *
		 * @param bool   $is_core Whether the file counts as core.
		 * @param string $file    Relative path.
		 */
		return (bool) apply_filters( 'teksecurity_integrity_is_core', $is_core, $file );
	}

	/**
	 * Fetch the official checksums for the installed WordPress version.
	 *
	 * @return array|null path => md5, or null when the API is unreachable.
	 */
	public static function official_checksums() {
		global $wp_version;

		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		$locale    = get_locale();
		$checksums = get_core_checksums( $wp_version, $locale );

		if ( ! is_array( $checksums ) && 'en_US' !== $locale ) {
			$checksums = get_core_checksums( $wp_version, 'en_US' );
		}

		return is_array( $checksums ) ? $checksums : null;
	}

	/**
	 * Run a full scan and store the results.
	 *
	 * @return array { @type int $checked, @type int $issues, @type string|null $error }
	 */
	public static function scan() {
		global $wpdb;

		$checksums = self::official_checksums();

		if ( null === $checksums ) {
			return array(
				'checked' => 0,
				'issues'  => 0,
				'error'   => __( 'WordPress.org did not return checksums for this version, so core files could not be compared.', 'teksecurity' ),
			);
		}

		$table   = Installer::table( 'integrity' );
		$ignored = self::ignored();
		$now     = current_time( 'mysql' );
		$checked = 0;
		$issues  = 0;

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$wpdb->query( "DELETE FROM {$table}" );

		foreach ( $checksums as $file => $expected ) {
			if ( in_array( $file, $ignored, true ) || ! self::is_core_path( $file ) ) {
				continue;
			}

			$path = ABSPATH . $file;
			++$checked;

			if ( ! file_exists( $path ) ) {
				self::record( $file, '', 'missing', 0, $now );
				++$issues;
				continue;
			}

			$actual = md5_file( $path );

			if ( $actual !== $expected ) {
				self::record( $file, (string) $actual, 'modified', (int) filesize( $path ), $now );
				++$issues;
			}
		}

		foreach ( self::unexpected_core_files( $checksums ) as $file ) {
			self::record( $file, (string) md5_file( ABSPATH . $file ), 'unknown', (int) filesize( ABSPATH . $file ), $now );
			++$issues;
		}

		update_option(
			self::LAST_SCAN_OPTION,
			array(
				'at'      => time(),
				'checked' => $checked,
				'issues'  => $issues,
			),
			false
		);

		/**
		 * Fires after an integrity scan finishes.
		 *
		 * @param int $issues  Problems found.
		 * @param int $checked Files compared.
		 */
		do_action( 'teksecurity_integrity_scanned', $issues, $checked );

		return array(
			'checked' => $checked,
			'issues'  => $issues,
			'error'   => null,
		);
	}

	/**
	 * PHP files sitting in wp-admin or wp-includes that core does not ship.
	 *
	 * @param array $checksums Official checksums.
	 * @return array Relative paths.
	 */
	protected static function unexpected_core_files( array $checksums ) {
		$found = array();

		foreach ( array( 'wp-admin', WPINC ) as $dir ) {
			$root = ABSPATH . $dir;

			if ( ! is_dir( $root ) ) {
				continue;
			}

			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS )
			);

			foreach ( $iterator as $item ) {
				if ( ! $item->isFile() || 'php' !== strtolower( $item->getExtension() ) ) {
					continue;
				}

				$relative = str_replace( '\\', '/', substr( $item->getPathname(), strlen( ABSPATH ) ) );

				if ( ! isset( $checksums[ $relative ] ) ) {
					$found[] = $relative;
				}
			}
		}

		return $found;
	}

	/**
	 * Store one finding.
	 *
	 * @param string $file     Relative path.
	 * @param string $checksum Actual checksum.
	 * @param string $status   modified|missing|unknown.
	 * @param int    $size     File size.
	 * @param string $now      Scan timestamp.
	 * @return void
	 */
	protected static function record( $file, $checksum, $status, $size, $now ) {
		global $wpdb;

		$wpdb->replace( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Installer::table( 'integrity' ),
			array(
				'file_path'  => substr( $file, 0, 255 ),
				'checksum'   => $checksum,
				'status'     => $status,
				'size_bytes' => $size,
				'scanned_at' => $now,
			)
		);
	}

	/**
	 * Current findings.
	 *
	 * @return array
	 */
	public static function issues() {
		global $wpdb;

		$table = Installer::table( 'integrity' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY status, file_path LIMIT 500", ARRAY_A );

		return array_map(
			static function ( $row ) {
				return array(
					'id'        => (int) $row['id'],
					'file'      => $row['file_path'],
					'status'    => $row['status'],
					'size'      => (int) $row['size_bytes'],
					'scannedAt' => $row['scanned_at'],
				);
			},
			(array) $rows
		);
	}

	/**
	 * Summary for the dashboard.
	 *
	 * @return array
	 */
	public static function summary() {
		$last = get_option( self::LAST_SCAN_OPTION, array() );

		return array(
			'enabled'    => (bool) Options::get( 'integrity.on', true ),
			'lastScanAt' => isset( $last['at'] ) ? gmdate( 'c', (int) $last['at'] ) : null,
			'checked'    => isset( $last['checked'] ) ? (int) $last['checked'] : 0,
			'issues'     => isset( $last['issues'] ) ? (int) $last['issues'] : 0,
		);
	}
}
