/**
 * Thin wrapper over the TekSecurity REST namespace.
 */

const boot = window.tekSecurityData || {};

/**
 * Build a URL with a query string.
 *
 * @param {string} path  Route path, e.g. "/traffic".
 * @param {Object} query Query parameters.
 * @return {string} Full URL.
 */
function buildUrl( path, query ) {
	const url = new URL( `${ boot.root }${ path }`, window.location.origin );

	Object.entries( query || {} ).forEach( ( [ key, value ] ) => {
		if ( value !== undefined && value !== null && value !== '' ) {
			url.searchParams.set( key, value );
		}
	} );

	return url.toString();
}

/**
 * Make a request and unwrap the JSON body.
 *
 * @param {string} method HTTP method.
 * @param {string} path   Route path.
 * @param {Object} body   JSON body for write requests.
 * @param {Object} query  Query parameters.
 * @return {Promise<Object>} Parsed response.
 * @throws {Error} When the API replies with an error status.
 */
async function request( method, path, body, query ) {
	const response = await fetch( buildUrl( path, query ), {
		method,
		credentials: 'same-origin',
		headers: {
			'Content-Type': 'application/json',
			'X-WP-Nonce': boot.nonce,
		},
		body: body ? JSON.stringify( body ) : undefined,
	} );

	const text = await response.text();
	const data = text ? JSON.parse( text ) : null;

	if ( ! response.ok ) {
		const error = new Error(
			( data && data.message ) ||
				'Something went wrong. Please try again.'
		);
		error.code = data && data.code;
		error.status = response.status;
		throw error;
	}

	return data;
}

export const api = {
	get: ( path, query ) => request( 'GET', path, null, query ),
	post: ( path, body ) => request( 'POST', path, body ),
	del: ( path, query ) => request( 'DELETE', path, null, query ),
};

export { boot };
