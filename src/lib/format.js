/**
 * Date, number and label formatting shared across the screens.
 */

import { __, _n, sprintf } from '@wordpress/i18n';

/**
 * Clock time for a log row, with a day prefix once it is not today.
 *
 * @param {string} iso ISO 8601 timestamp.
 * @return {string} Formatted time.
 */
export function logTime( iso ) {
	const date = new Date( iso );
	const time = date.toLocaleTimeString( undefined, {
		hour: '2-digit',
		minute: '2-digit',
		hour12: false,
	} );

	const days = daysAgo( date );

	if ( days === 0 ) {
		return time;
	}

	if ( days === 1 ) {
		return sprintf(
			/* translators: %s: clock time, e.g. "14:28". */
			__( 'Yesterday %s', 'teksecurity' ),
			time
		);
	}

	return `${ date.toLocaleDateString( undefined, {
		month: 'short',
		day: 'numeric',
	} ) }, ${ time }`;
}

/**
 * Relative time, e.g. "12 min ago".
 *
 * @param {string} iso ISO 8601 timestamp.
 * @return {string} Formatted distance.
 */
export function timeAgo( iso ) {
	if ( ! iso ) {
		return '';
	}

	const minutes = Math.round( ( Date.now() - new Date( iso ) ) / 60000 );

	if ( minutes < 1 ) {
		return __( 'just now', 'teksecurity' );
	}

	if ( minutes < 60 ) {
		return sprintf(
			/* translators: %d: number of minutes. */
			_n( '%d min ago', '%d min ago', minutes, 'teksecurity' ),
			minutes
		);
	}

	if ( minutes < 1440 ) {
		const hours = Math.floor( minutes / 60 );
		return sprintf(
			/* translators: %d: number of hours. */
			_n( '%d h ago', '%d h ago', hours, 'teksecurity' ),
			hours
		);
	}

	return logTime( iso );
}

/**
 * Full date and time for the drawer header.
 *
 * @param {string} iso ISO 8601 timestamp.
 * @return {string} Formatted date and time.
 */
export function fullTime( iso ) {
	const date = new Date( iso );
	const time = logTime( iso );

	return daysAgo( date ) === 0
		? sprintf(
				/* translators: %s: clock time. */
				__( 'Today %s', 'teksecurity' ),
				time
		  )
		: time;
}

/**
 * A weekday label for the dashboard chart.
 *
 * @param {string} date  Y-m-d date string.
 * @param {number} index Position in the series.
 * @param {number} last  Index of the final bar.
 * @return {string} Label.
 */
export function dayLabel( date, index, last ) {
	if ( index === last ) {
		return __( 'Today', 'teksecurity' );
	}

	return new Date( `${ date }T00:00:00` ).toLocaleDateString( undefined, {
		weekday: 'short',
	} );
}

/**
 * Whole days between a date and now.
 *
 * @param {Date} date Date to measure.
 * @return {number} Day count.
 */
function daysAgo( date ) {
	const start = new Date();
	start.setHours( 0, 0, 0, 0 );

	const other = new Date( date );
	other.setHours( 0, 0, 0, 0 );

	return Math.round( ( start - other ) / 86400000 );
}
