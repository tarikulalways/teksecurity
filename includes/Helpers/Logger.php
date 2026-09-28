<?php
/**
 * Traffic log reader and writer.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Helpers;

use TekSecurity\Core\Installer;
use TekSecurity\Core\Options;
use TekSecurity\Helpers\Rules;

defined( 'ABSPATH' ) || exit;

/**
 * Every firewall decision goes through here.
 */
class Logger {

	/**
	 * Record a blocked or logged request.
	 *
	 * @param array $event {
	 *     @type string $attack_type One of the keys in Firewall::types().
	 *     @type string $rule_id     Rule identifier, e.g. TS-SQLI-1003.
	 *     @type string $rule_name   Human readable rule name.
	 *     @type string $action      blocked|logged.
	 *     @type string $method      HTTP method.
	 *     @type string $path        Request URI.
	 *     @type string $matched_in  Where the payload was found.
	 *     @type string $payload     The offending value.
	 * }
	 * @return int Inserted row id, or 0 on failure.
	 */
	public static function record( array $event ) {
		global $wpdb;

		$ip = isset( $event['ip'] ) ? $event['ip'] : Ip::current();

		$row = array(
			'created_at'  => current_time( 'mysql' ),
			'attack_type' => substr( (string) ( $event['attack_type'] ?? '' ), 0, 32 ),
			'rule_id'     => substr( (string) ( $event['rule_id'] ?? '' ), 0, 40 ),
			'rule_name'   => substr( (string) ( $event['rule_name'] ?? '' ), 0, 190 ),
			'action'      => 'logged' === ( $event['action'] ?? '' ) ? 'logged' : 'blocked',
			'method'      => substr( (string) ( $event['method'] ?? 'GET' ), 0, 10 ),
			'path'        => substr( (string) ( $event['path'] ?? '' ), 0, 2000 ),
			'matched_in'  => substr( (string) ( $event['matched_in'] ?? '' ), 0, 190 ),
			'payload'     => substr( (string) ( $event['payload'] ?? '' ), 0, 2000 ),
			'ip'          => substr( (string) $ip, 0, 45 ),
			'country'     => substr( (string) ( $event['country'] ?? Ip::country( $ip ) ), 0, 2 ),
			'user_agent'  => substr( (string) ( $event['user_agent'] ?? Ip::user_agent() ), 0, 500 ),
			'user_id'     => (int) ( $event['user_id'] ?? get_current_user_id() ),
		);

		$inserted = $wpdb->insert( Installer::table( 'events' ), $row ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

		if ( ! $inserted ) {
			return 0;
		}

		$id  = (int) $wpdb->insert_id;
		$row['id'] = $id;

		/**
		 * Fires after a firewall event has been written to the log.
		 *
		 * @param array $row The stored row.
		 */
		do_action( 'teksecurity_event_logged', $row );

		return $id;
	}

	/**
	 * Query the traffic log.
	 *
	 * @param array $args {
	 *     @type string $search   Free text over IP, path, rule and type.
	 *     @type string $action   all|blocked|logged.
	 *     @type string $type     all|<attack type>.
	 *     @type int    $page     Zero-based page index.
	 *     @type int    $per_page Rows per page.
	 *     @type int    $days     Restrict to the last N days.
	 * }
	 * @return array { @type array $rows, @type int $total }
	 */
	public static function query( array $args = array() ) {
		global $wpdb;

		$args = wp_parse_args(
			$args,
			array(
				'search'   => '',
				'action'   => 'all',
				'type'     => 'all',
				'page'     => 0,
				'per_page' => 12,
				'days'     => 0,
			)
		);

		$table  = Installer::table( 'events' );
		$where  = array( '1=1' );
		$params = array();

		if ( 'all' !== $args['action'] && '' !== $args['action'] ) {
			$where[]  = 'action = %s';
			$params[] = strtolower( $args['action'] );
		}

		if ( 'all' !== $args['type'] && '' !== $args['type'] ) {
			$where[]  = 'attack_type = %s';
			$params[] = $args['type'];
		}

		if ( $args['days'] > 0 ) {
			$where[]  = 'created_at >= %s';
			$params[] = gmdate( 'Y-m-d H:i:s', strtotime( '-' . (int) $args['days'] . ' days', self::now() ) );
		}

		if ( '' !== trim( (string) $args['search'] ) ) {
			$like     = '%' . $wpdb->esc_like( trim( $args['search'] ) ) . '%';
			$where[]  = '(ip LIKE %s OR path LIKE %s OR rule_id LIKE %s OR attack_type LIKE %s OR rule_name LIKE %s)';
			$params   = array_merge( $params, array( $like, $like, $like, $like, $like ) );
		}

		// $clause is built above from this method's own fixed fragments; every
		// value the caller supplied travels as a placeholder in $params.
		$clause   = implode( ' AND ', $where );
		$per_page = max( 1, min( 100, (int) $args['per_page'] ) );
		$offset   = max( 0, (int) $args['page'] ) * $per_page;

		// The placeholders live inside $clause, which is assembled above, so the
		// sniffs that count them statically cannot see them.
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders
		if ( $params ) {
			$total = (int) $wpdb->get_var(
				$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE {$clause}", $params )
			);
		} else {
			$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$clause}" );
		}

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE {$clause} ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d",
				array_merge( $params, array( $per_page, $offset ) )
			),
			ARRAY_A
		);
		// phpcs:enable

		return array(
			'rows'  => array_map( array( __CLASS__, 'shape' ), (array) $rows ),
			'total' => $total,
		);
	}

	/**
	 * Fetch a single event.
	 *
	 * @param int $id Event id.
	 * @return array|null
	 */
	public static function find( $id ) {
		global $wpdb;

		$table = Installer::table( 'events' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", (int) $id ), ARRAY_A );

		return $row ? self::shape( $row ) : null;
	}

	/**
	 * Count events grouped by attack type within a window.
	 *
	 * @param int $days Window in days.
	 * @return array type => count
	 */
	public static function counts_by_type( $days = 7 ) {
		global $wpdb;

		$table = Installer::table( 'events' );
		$since = gmdate( 'Y-m-d H:i:s', strtotime( '-' . (int) $days . ' days', self::now() ) );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT attack_type, COUNT(*) AS total FROM {$table} WHERE created_at >= %s GROUP BY attack_type", $since ), ARRAY_A );

		$out = array();
		foreach ( (array) $rows as $row ) {
			$out[ $row['attack_type'] ] = (int) $row['total'];
		}

		return $out;
	}

	/**
	 * Blocked counts for each of the last N days, oldest first.
	 *
	 * @param int $days Number of days including today.
	 * @return array List of [ 'date' => Y-m-d, 'total' => int ].
	 */
	public static function blocked_by_day( $days = 7 ) {
		global $wpdb;

		$table = Installer::table( 'events' );
		$since = gmdate( 'Y-m-d 00:00:00', strtotime( '-' . ( (int) $days - 1 ) . ' days', self::now() ) );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT DATE(created_at) AS day, COUNT(*) AS total FROM {$table} WHERE action = 'blocked' AND created_at >= %s GROUP BY DATE(created_at)", $since ), ARRAY_A );

		$totals = array();
		foreach ( (array) $rows as $row ) {
			$totals[ $row['day'] ] = (int) $row['total'];
		}

		$series = array();
		for ( $i = (int) $days - 1; $i >= 0; $i-- ) {
			$date     = gmdate( 'Y-m-d', strtotime( '-' . $i . ' days', self::now() ) );
			$series[] = array(
				'date'  => $date,
				'total' => isset( $totals[ $date ] ) ? $totals[ $date ] : 0,
			);
		}

		return $series;
	}

	/**
	 * Aggregate numbers for the dashboard.
	 *
	 * @return array
	 */
	public static function summary() {
		global $wpdb;

		$table = Installer::table( 'events' );
		$today = gmdate( 'Y-m-d 00:00:00', self::now() );
		$yest  = gmdate( 'Y-m-d 00:00:00', strtotime( '-1 day', self::now() ) );
		$week  = gmdate( 'Y-m-d H:i:s', strtotime( '-7 days', self::now() ) );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$blocked_today = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE action = 'blocked' AND created_at >= %s", $today ) );
		$blocked_yest  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE action = 'blocked' AND created_at >= %s AND created_at < %s", $yest, $today ) );
		$blocked_week  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE action = 'blocked' AND created_at >= %s", $week ) );
		$logged_week   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE action = 'logged' AND created_at >= %s", $week ) );
		$unique_ips    = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT ip) FROM {$table} WHERE created_at >= %s", $week ) );
		$last_blocked  = $wpdb->get_var( $wpdb->prepare( "SELECT created_at FROM {$table} WHERE action = 'blocked' AND created_at >= %s ORDER BY created_at DESC LIMIT 1", $week ) );
		// phpcs:enable

		return array(
			'blocked_today'     => $blocked_today,
			'blocked_yesterday' => $blocked_yest,
			'blocked_week'      => $blocked_week,
			'logged_week'       => $logged_week,
			'unique_ips'        => $unique_ips,
			'last_blocked_at'   => $last_blocked ? self::to_iso( $last_blocked ) : null,
		);
	}

	/**
	 * Delete events older than the retention window.
	 *
	 * @return int Rows removed.
	 */
	public static function prune() {
		global $wpdb;

		$days  = max( 1, (int) Options::get( 'data.retention', 30 ) );
		$table = Installer::table( 'events' );
		$since = gmdate( 'Y-m-d H:i:s', strtotime( '-' . $days . ' days', self::now() ) );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $since ) );
	}

	/**
	 * Normalise a database row for the REST API.
	 *
	 * @param array $row Raw row.
	 * @return array
	 */
	protected static function shape( array $row ) {
		return array(
			'id'         => (int) $row['id'],
			'createdAt'  => self::to_iso( $row['created_at'] ),
			'type'       => $row['attack_type'],
			'ruleId'     => $row['rule_id'],
			// Names are stored in English; translate on the way out.
			'ruleName'   => Rules::rule_name( $row['rule_id'], $row['rule_name'] ),
			'action'     => $row['action'],
			'method'     => $row['method'],
			'path'       => $row['path'],
			'matchedIn'  => $row['matched_in'],
			'payload'    => $row['payload'],
			'ip'         => $row['ip'],
			'country'    => $row['country'],
			'userAgent'  => $row['user_agent'],
			'userId'     => (int) $row['user_id'],
		);
	}

	/**
	 * Convert a site-local MySQL datetime to an ISO 8601 string.
	 *
	 * @param string $mysql Datetime.
	 * @return string
	 */
	protected static function to_iso( $mysql ) {
		return gmdate( 'c', (int) get_gmt_from_date( $mysql, 'U' ) );
	}

	/**
	 * Current site-local timestamp.
	 *
	 * @return int
	 */
	protected static function now() {
		return (int) current_time( 'timestamp' ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp
	}
}
