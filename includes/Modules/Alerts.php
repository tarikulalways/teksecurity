<?php
/**
 * Email alerts and the weekly summary.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Modules;

use TekSecurity\Core\Options;
use TekSecurity\Helpers\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * Decides what is worth an email and sends it.
 */
class Alerts {

	const THROTTLE_KEY = 'teksecurity_alert_sent';

	/**
	 * Attack types treated as critical.
	 *
	 * @return array
	 */
	public static function critical_types() {
		/**
		 * Filter which attack types count as critical for alerting.
		 *
		 * @param array $types Attack type keys.
		 */
		return apply_filters( 'teksecurity_critical_types', array( 'sqli', 'exploit', 'plugin', 'priv', 'upload' ) );
	}

	/**
	 * Hook in.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'teksecurity_event_logged', array( $this, 'maybe_alert' ) );
		add_action( 'teksecurity_ip_locked_out', array( $this, 'alert_lockout' ), 10, 3 );
		add_action( 'teksecurity_integrity_scanned', array( $this, 'alert_integrity' ), 10, 2 );
	}

	/**
	 * Send an alert for a logged event when the settings ask for one.
	 *
	 * @param array $event Stored event row.
	 * @return void
	 */
	public function maybe_alert( array $event ) {
		$level = Options::get( 'alerts.alerts', 'critical' );

		if ( 'off' === $level ) {
			return;
		}

		if ( 'critical' === $level && ! in_array( $event['attack_type'], self::critical_types(), true ) ) {
			return;
		}

		if ( 'blocked' !== $event['action'] ) {
			return;
		}

		// One email per attack type per hour keeps a burst from flooding the inbox.
		$throttle = self::THROTTLE_KEY . '_' . $event['attack_type'];

		if ( get_transient( $throttle ) ) {
			return;
		}

		set_transient( $throttle, 1, HOUR_IN_SECONDS );

		$this->send(
			sprintf(
				/* translators: 1: attack type, 2: site name. */
				__( '[%1$s] Attack blocked on %2$s', 'teksecurity' ),
				ucfirst( str_replace( '_', ' ', $event['attack_type'] ) ),
				self::site_name()
			),
			sprintf(
				/* translators: 1: rule name, 2: IP address, 3: method and path, 4: admin URL. */
				__( "TekSecurity blocked a request on %4\$s.\n\nRule: %1\$s\nFrom: %2\$s\nRequest: %3\$s\n\nOpen the traffic log: %5\$s", 'teksecurity' ),
				$event['rule_name'],
				$event['ip'],
				$event['method'] . ' ' . $event['path'],
				home_url(),
				admin_url( 'admin.php?page=teksecurity#/traffic' )
			)
		);
	}

	/**
	 * Tell the owner when an IP has been locked out.
	 *
	 * @param string $ip       Address.
	 * @param string $username Last username tried.
	 * @param int    $attempts Failed attempts.
	 * @return void
	 */
	public function alert_lockout( $ip, $username, $attempts ) {
		if ( 'off' === Options::get( 'alerts.alerts', 'critical' ) ) {
			return;
		}

		if ( get_transient( self::THROTTLE_KEY . '_lockout' ) ) {
			return;
		}

		set_transient( self::THROTTLE_KEY . '_lockout', 1, HOUR_IN_SECONDS );

		$this->send(
			sprintf(
				/* translators: %s: site name. */
				__( '[Brute force] An IP was locked out on %s', 'teksecurity' ),
				self::site_name()
			),
			sprintf(
				/* translators: 1: IP address, 2: attempts, 3: username, 4: admin URL. */
				__( "%1\$s was locked out after %2\$d failed sign-in attempts as “%3\$s”.\n\nReview lockouts: %4\$s", 'teksecurity' ),
				$ip,
				(int) $attempts,
				$username,
				admin_url( 'admin.php?page=teksecurity#/login' )
			)
		);
	}

	/**
	 * Tell the owner when core files changed.
	 *
	 * @param int $issues  Problems found.
	 * @param int $checked Files compared.
	 * @return void
	 */
	public function alert_integrity( $issues, $checked ) {
		if ( $issues < 1 || 'off' === Options::get( 'alerts.alerts', 'critical' ) ) {
			return;
		}

		$this->send(
			sprintf(
				/* translators: %s: site name. */
				__( '[Integrity] Core files changed on %s', 'teksecurity' ),
				self::site_name()
			),
			sprintf(
				/* translators: 1: number of problems, 2: files compared, 3: admin URL. */
				__( "The integrity scan found %1\$d problem(s) across %2\$d core files.\n\nReview the findings: %3\$s", 'teksecurity' ),
				(int) $issues,
				(int) $checked,
				admin_url( 'admin.php?page=teksecurity#/settings' )
			)
		);
	}

	/**
	 * Build and send the weekly summary.
	 *
	 * @return bool
	 */
	public function send_weekly_summary() {
		if ( ! Options::get( 'alerts.weekly', true ) ) {
			return false;
		}

		$summary  = Logger::summary();
		$counts   = Logger::counts_by_type( 7 );
		$exposed  = Vulnerability::exposed();
		$lockouts = Login::lockouts();

		arsort( $counts );
		$lines = array();

		foreach ( array_slice( $counts, 0, 5, true ) as $type => $total ) {
			$types   = \TekSecurity\Helpers\Rules::types();
			$label   = isset( $types[ $type ] ) ? $types[ $type ]['label'] : $type;
			$lines[] = sprintf( '  %s: %d', $label, $total );
		}

		$body = sprintf(
			/* translators: 1: site name, 2: blocked count, 3: logged count, 4: unique IPs. */
			__( "Here is what TekSecurity did on %1\$s this week.\n\nBlocked requests: %2\$d\nLogged only: %3\$d\nAttacking IPs: %4\$d\n", 'teksecurity' ),
			self::site_name(),
			$summary['blocked_week'],
			$summary['logged_week'],
			$summary['unique_ips']
		);

		if ( $lines ) {
			$body .= "\n" . __( 'Top attack types:', 'teksecurity' ) . "\n" . implode( "\n", $lines ) . "\n";
		}

		if ( $exposed ) {
			$body .= "\n" . sprintf(
				/* translators: %s: comma separated plugin names. */
				__( 'Plugins that need attention: %s', 'teksecurity' ),
				implode( ', ', wp_list_pluck( $exposed, 'name' ) )
			) . "\n";
		}

		if ( $lockouts ) {
			$body .= "\n" . sprintf(
				/* translators: %d: number of locked out IPs. */
				_n( '%d IP is locked out right now.', '%d IPs are locked out right now.', count( $lockouts ), 'teksecurity' ),
				count( $lockouts )
			) . "\n";
		}

		$body .= "\n" . sprintf(
			/* translators: %s: admin URL. */
			__( 'Open the dashboard: %s', 'teksecurity' ),
			admin_url( 'admin.php?page=teksecurity' )
		);

		return $this->send(
			sprintf(
				/* translators: %s: site name. */
				__( 'Weekly security summary for %s', 'teksecurity' ),
				self::site_name()
			),
			$body
		);
	}

	/**
	 * Send one email to the configured alert address.
	 *
	 * @param string $subject Subject line.
	 * @param string $body    Plain text body.
	 * @return bool
	 */
	protected function send( $subject, $body ) {
		$to = Options::get( 'alerts.email', get_option( 'admin_email' ) );

		if ( ! is_email( $to ) ) {
			return false;
		}

		/**
		 * Filter a TekSecurity alert before it is sent.
		 *
		 * @param array $mail { @type string $to, @type string $subject, @type string $body }
		 */
		$mail = apply_filters(
			'teksecurity_alert_mail',
			array(
				'to'      => $to,
				'subject' => $subject,
				'body'    => $body,
			)
		);

		return wp_mail( $mail['to'], $mail['subject'], $mail['body'] );
	}

	/**
	 * Decoded site name.
	 *
	 * @return string
	 */
	protected static function site_name() {
		return wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
	}
}
