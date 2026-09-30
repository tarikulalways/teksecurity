/**
 * The load-and-save cycle every settings screen shares.
 */

import { useCallback, useEffect, useState } from '@wordpress/element';

import { api } from './api';

/**
 * Fetch a REST resource on mount and keep it in step with writes.
 *
 * Every screen in this admin does the same three things: read one endpoint
 * into state, write back to it, and replace the state with whatever the server
 * returns. Keeping that in one place means a screen only describes what it
 * shows, and the error and refresh behaviour cannot drift between screens.
 *
 * @param {string}   path            REST path relative to the namespace, e.g. "/firewall".
 * @param {Object}   options         Options.
 * @param {Function} options.toast   Show a toast.
 * @param {Function} options.refresh Refresh the shell's badges after a write.
 * @return {Object} { data, setData, reload, save, mutate }
 */
export function useResource( path, { toast, refresh } ) {
	const [ data, setData ] = useState( null );

	const reload = useCallback(
		() => api.get( path ).then( setData ),
		[ path ]
	);

	useEffect( () => {
		let cancelled = false;

		api.get( path )
			.then( ( next ) => {
				if ( ! cancelled ) {
					setData( next );
				}
			} )
			.catch( ( error ) => toast( error.message, 'error' ) );

		return () => {
			cancelled = true;
		};
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [ path ] );

	/**
	 * Run a write, adopt its response, and report the outcome.
	 *
	 * @param {Function} request       Returns the request promise.
	 * @param {Object}   config        Options.
	 * @param {string}   config.message Toast to show when it succeeds.
	 * @param {boolean}  config.merge   Merge the response into state instead of replacing it.
	 * @param {boolean}  config.inline  Re-throw instead of toasting, so the caller
	 *                                  can put the message next to the field.
	 * @return {Promise<boolean>} Whether it succeeded.
	 */
	const mutate = useCallback(
		async ( request, { message, merge = false, inline = false } = {} ) => {
			try {
				const next = await request();

				setData( ( current ) =>
					merge ? { ...current, ...next } : next
				);
				refresh();

				if ( message ) {
					toast( message );
				}

				return true;
			} catch ( error ) {
				if ( inline ) {
					throw error;
				}

				toast( error.message, 'error' );
				return false;
			}
		},
		// eslint-disable-next-line react-hooks/exhaustive-deps
		[]
	);

	/**
	 * POST a patch to this resource's own endpoint.
	 *
	 * @param {Object} payload Body.
	 * @param {string} message Toast to show when it succeeds.
	 * @return {Promise<boolean>} Whether it succeeded.
	 */
	const save = useCallback(
		( payload, message ) =>
			mutate( () => api.post( path, payload ), { message } ),
		[ mutate, path ]
	);

	return { data, setData, reload, save, mutate };
}
