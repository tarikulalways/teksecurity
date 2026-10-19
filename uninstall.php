<?php
/**
 * Removes every trace of TekSecurity when the plugin is deleted.
 *
 * @package TekSecurity
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

require_once __DIR__ . '/includes/Core/Autoloader.php';

if ( ! defined( 'TEKSEC_PATH' ) ) {
	define( 'TEKSEC_PATH', plugin_dir_path( __FILE__ ) );
}

TekSecurity\Core\Autoloader::register();
TekSecurity\Core\Installer::drop_tables();

$teksec_options = array(
	'teksecurity_settings',
	'teksecurity_db_version',
	'teksecurity_installed_at',
	'teksecurity_integrity_last_scan',
	'teksecurity_job_integrity_scan',
	'teksecurity_job_vulnerability_scan',
	'teksecurity_job_prune_logs',
	'teksecurity_job_weekly_summary',
);

foreach ( $teksec_options as $teksec_option ) {
	delete_option( $teksec_option );
}

$teksec_meta = array(
	'_teksec_2fa_required',
	'_teksec_2fa_method',
	'_teksec_2fa_secret',
	'_teksec_2fa_pending_secret',
	'_teksec_2fa_backup_codes',
	'_teksec_2fa_enabled_at',
	'_teksec_2fa_reminded_at',
	'_teksec_2fa_trusted',
	'_teksec_2fa_email_code',
	'_teksec_2fa_login_token',
);

foreach ( $teksec_meta as $teksec_key ) {
	delete_metadata( 'user', 0, $teksec_key, '', true );
}

TekSecurity\Jobs\Scheduler::unschedule();
