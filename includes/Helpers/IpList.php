<?php
/**
 * Blocklist and allowlist storage.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Helpers;

use TekSecurity\Core\Installer;
use WP_Error;

defined( 'ABSPATH' ) || exit;

/**
 * Reads and writes the two IP lists.
 */
class IpList {

	/**
	 * Runtime cache keyed by list type.
	 *
	 * @var array
	 */
	protected static $cache = array();

	/**
	 * Every entry in a list.
	 *
	 * @param string $type block|allow.
	 * @return array
	 */
	public static function all( $type = 'block' ) {
		global $wpdb;

		$type = 'allow' === $type ? 'allow' : 'block';

		if ( ! isset( self::$cache[ $type ] ) ) {
			$table = Installer::table( 'ips' );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, ip, note, created_at FROM {$table} WHERE list_type = %s ORDER BY created_at DESC, id DESC", $type ), ARRAY_A );

			self::$cache[ $type ] = array_map(
				static function ( $row ) {
					return array(
						'id'        => (int) $row['id'],
						'ip'        => $row['ip'],
						'note'      => $row['note'],
						'createdAt' => $row['created_at'],
					);
				},
				(array) $rows
			);
		}

		return self::$cache[ $type ];
	}

	/**
	 * Add an entry.
	 *
	 * @param string $type block|allow.
	 * @param string $ip   Address or CIDR range.
	 * @param string $note Optional note.
	 * @return array|WP_Error
	 */
	public static function add( $type, $ip, $note = '' ) {
		global $wpdb;

		$type = 'allow' === $type ? 'allow' : 'block';
		$ip   = trim( (string) $ip );

		if ( ! Ip::is_valid( $ip ) ) {
			return new WP_Error(
				'teksecurity_invalid_ip',
				__( 'Enter a valid IPv4 address or range, like 203.0.113.7 or 203.0.113.0/24.', 'teksecurity' ),
				array( 'status' => 400 )
			);
		}

		$other = 'block' === $type ? 'allow' : 'block';

		foreach ( self::all( $type ) as $row ) {
			if ( $row['ip'] === $ip ) {
				return new WP_Error(
					'teksecurity_duplicate_ip',
					__( 'This IP is already in the list.', 'teksecurity' ),
					array( 'status' => 409 )
				);
			}
		}

		foreach ( self::all( $other ) as $row ) {
			if ( $row['ip'] === $ip ) {
				return new WP_Error(
					'teksecurity_ip_in_other_list',
					'block' === $other
						? __( 'This IP is in the blocklist. Remove it there first.', 'teksecurity' )
						: __( 'This IP is in the allowlist. Remove it there first.', 'teksecurity' ),
					array( 'status' => 409 )
				);
			}
		}

		if ( 'block' === $type && Ip::matches( Ip::current(), $ip ) ) {
			return new WP_Error(
				'teksecurity_self_block',
				__( 'That range covers your own IP address, so blocking it would lock you out.', 'teksecurity' ),
				array( 'status' => 400 )
			);
		}

		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Installer::table( 'ips' ),
			array(
				'list_type'  => $type,
				'ip'         => $ip,
				'note'       => substr( sanitize_text_field( $note ), 0, 190 ),
				'created_at' => current_time( 'mysql' ),
			)
		);

		unset( self::$cache[ $type ] );

		return array(
			'id'        => (int) $wpdb->insert_id,
			'ip'        => $ip,
			'note'      => sanitize_text_field( $note ),
			'createdAt' => current_time( 'mysql' ),
		);
	}

	/**
	 * Remove an entry by id.
	 *
	 * @param int $id Row id.
	 * @return bool
	 */
	public static function remove( $id ) {
		global $wpdb;

		self::$cache = array();

		return (bool) $wpdb->delete( Installer::table( 'ips' ), array( 'id' => (int) $id ), array( '%d' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Whether an IP is on the blocklist.
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	public static function is_blocked( $ip ) {
		foreach ( self::all( 'block' ) as $row ) {
			if ( Ip::matches( $ip, $row['ip'] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether an IP is on the allowlist and skips every check.
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	public static function is_allowed( $ip ) {
		foreach ( self::all( 'allow' ) as $row ) {
			if ( Ip::matches( $ip, $row['ip'] ) ) {
				return true;
			}
		}

		return false;
	}
}
