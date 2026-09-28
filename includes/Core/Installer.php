<?php
/**
 * Activation, database schema and upgrades.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Core;

use TekSecurity\Jobs\Scheduler;

defined( 'ABSPATH' ) || exit;

/**
 * Creates the plugin tables and seeds default settings.
 */
class Installer {

	const DB_VERSION_OPTION = 'teksecurity_db_version';

	/**
	 * Table name for a logical table key.
	 *
	 * @param string $key events|ips|lockouts|exclusions|integrity|vulnerabilities.
	 * @return string
	 */
	public static function table( $key ) {
		global $wpdb;

		return $wpdb->prefix . 'teksec_' . $key;
	}

	/**
	 * Run on activation.
	 *
	 * @return void
	 */
	public static function activate() {
		self::install_tables();

		$settings = Options::all();
		if ( '' === $settings['alerts']['email'] ) {
			$settings['alerts']['email'] = get_option( 'admin_email' );
		}
		Options::save( $settings );

		Scheduler::schedule();

		update_option( self::DB_VERSION_OPTION, TEKSEC_DB_VERSION, false );

		if ( false === get_option( 'teksecurity_installed_at' ) ) {
			add_option( 'teksecurity_installed_at', time(), '', false );
		}

		flush_rewrite_rules();
	}

	/**
	 * Run on deactivation.
	 *
	 * @return void
	 */
	public static function deactivate() {
		Scheduler::unschedule();
		flush_rewrite_rules();
	}

	/**
	 * Create or upgrade tables when the schema version moves.
	 *
	 * @return void
	 */
	public static function maybe_upgrade() {
		if ( get_option( self::DB_VERSION_OPTION ) === TEKSEC_DB_VERSION ) {
			return;
		}

		self::install_tables();
		Scheduler::schedule();
		update_option( self::DB_VERSION_OPTION, TEKSEC_DB_VERSION, false );
	}

	/**
	 * Create every table via dbDelta.
	 *
	 * @return void
	 */
	public static function install_tables() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$events  = self::table( 'events' );
		$ips     = self::table( 'ips' );
		$locks   = self::table( 'lockouts' );
		$excl    = self::table( 'exclusions' );
		$integ   = self::table( 'integrity' );
		$vulns   = self::table( 'vulnerabilities' );

		dbDelta(
			"CREATE TABLE {$events} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at datetime NOT NULL,
				attack_type varchar(32) NOT NULL DEFAULT '',
				rule_id varchar(40) NOT NULL DEFAULT '',
				rule_name varchar(190) NOT NULL DEFAULT '',
				action varchar(16) NOT NULL DEFAULT 'blocked',
				method varchar(10) NOT NULL DEFAULT 'GET',
				path text NOT NULL,
				matched_in varchar(190) NOT NULL DEFAULT '',
				payload text NOT NULL,
				ip varchar(45) NOT NULL DEFAULT '',
				country varchar(2) NOT NULL DEFAULT '',
				user_agent text NOT NULL,
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY attack_type (attack_type),
				KEY ip (ip),
				KEY action (action)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$ips} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				list_type varchar(8) NOT NULL DEFAULT 'block',
				ip varchar(45) NOT NULL DEFAULT '',
				note varchar(190) NOT NULL DEFAULT '',
				created_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY list_ip (list_type,ip),
				KEY ip (ip)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$locks} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				ip varchar(45) NOT NULL DEFAULT '',
				country varchar(2) NOT NULL DEFAULT '',
				username varchar(190) NOT NULL DEFAULT '',
				tries smallint(5) unsigned NOT NULL DEFAULT 0,
				created_at datetime NOT NULL,
				expires_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY ip (ip),
				KEY expires_at (expires_at)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$excl} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				rule_id varchar(40) NOT NULL DEFAULT '',
				path varchar(190) NOT NULL DEFAULT '',
				created_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY rule_path (rule_id,path)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$integ} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				file_path varchar(255) NOT NULL DEFAULT '',
				checksum varchar(64) NOT NULL DEFAULT '',
				status varchar(16) NOT NULL DEFAULT 'ok',
				size_bytes bigint(20) unsigned NOT NULL DEFAULT 0,
				scanned_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY file_path (file_path),
				KEY status (status)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$vulns} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				slug varchar(190) NOT NULL DEFAULT '',
				name varchar(190) NOT NULL DEFAULT '',
				installed_version varchar(32) NOT NULL DEFAULT '',
				fixed_version varchar(32) NOT NULL DEFAULT '',
				severity varchar(16) NOT NULL DEFAULT '',
				issue text NOT NULL,
				patch_id varchar(40) NOT NULL DEFAULT '',
				shield tinyint(1) NOT NULL DEFAULT 1,
				updated_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY slug (slug)
			) {$charset};"
		);
	}

	/**
	 * Drop every table. Used by uninstall.php.
	 *
	 * @return void
	 */
	public static function drop_tables() {
		global $wpdb;

		foreach ( array( 'events', 'ips', 'lockouts', 'exclusions', 'integrity', 'vulnerabilities' ) as $key ) {
			$table = self::table( $key );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		}
	}
}
