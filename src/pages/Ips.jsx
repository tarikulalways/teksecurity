/**
 * IP lists screen.
 */

import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import { useResource } from '../lib/useResource';
import { Loading } from '../components/primitives';

/**
 * The blocklist and the allowlist.
 *
 * @param {Object}   props         Component props.
 * @param {Function} props.toast   Show a toast.
 * @param {Function} props.refresh Refresh the shell's badges.
 * @return {JSX.Element} The screen.
 */
export default function Ips( { toast, refresh } ) {
	const { data, mutate } = useResource( '/ips', { toast, refresh } );
	const [ tab, setTab ] = useState( 'block' );
	const [ ip, setIp ] = useState( '' );
	const [ note, setNote ] = useState( '' );
	const [ error, setError ] = useState( '' );

	if ( ! data ) {
		return <Loading />;
	}

	// A rejected address is explained beside the field, not in a toast that
	// disappears before the reason has been read.
	const add = async () => {
		try {
			await mutate( () => api.post( '/ips', { list: tab, ip, note } ), {
				inline: true,
				message:
					tab === 'block'
						? sprintf(
								/* translators: %s: IP address that was added to the blocklist. */
								__( '%s blocked', 'teksecurity' ),
								ip
						  )
						: sprintf(
								/* translators: %s: IP address that was added to the allowlist. */
								__( '%s allowed', 'teksecurity' ),
								ip
						  ),
			} );
			setIp( '' );
			setNote( '' );
			setError( '' );
		} catch ( addError ) {
			setError( addError.message );
		}
	};

	const remove = ( row ) =>
		mutate( () => api.del( `/ips/${ row.id }` ), {
			message: sprintf(
				/* translators: %s: IP address. */
				__( '%s removed', 'teksecurity' ),
				row.ip
			),
		} );

	const rows = data[ tab ];

	return (
		<div className="ts-stack">
			<div className="ts-tabs">
				{ [
					[ 'block', __( 'Blocklist', 'teksecurity' ) ],
					[ 'allow', __( 'Allowlist', 'teksecurity' ) ],
				].map( ( [ key, label ] ) => (
					<button
						key={ key }
						type="button"
						aria-pressed={ tab === key }
						className={ `ts-tab${
							tab === key ? ' ts-tab--active' : ''
						}` }
						onClick={ () => {
							setTab( key );
							setError( '' );
						} }
					>
						{ label } ({ data[ key ].length })
					</button>
				) ) }
			</div>

			<div className="ts-inline-form">
				<div className="ts-inline-form__field">
					<input
						className={ `ts-input${
							error ? ' ts-input--error' : ''
						}` }
						value={ ip }
						placeholder={ __(
							'IP or range, e.g. 203.0.113.0/24',
							'teksecurity'
						) }
						aria-label={ __(
							'IP address or range',
							'teksecurity'
						) }
						onChange={ ( event ) => {
							setIp( event.target.value );
							setError( '' );
						} }
						onKeyDown={ ( event ) => {
							if ( event.key === 'Enter' ) {
								add();
							}
						} }
					/>
					{ error && (
						<div className="ts-hint ts-hint--error ts-inline-error">
							{ error }
						</div>
					) }
				</div>
				<input
					className="ts-input ts-inline-form__field"
					value={ note }
					placeholder={ __( 'Note (optional)', 'teksecurity' ) }
					aria-label={ __( 'Note', 'teksecurity' ) }
					onChange={ ( event ) => setNote( event.target.value ) }
					onKeyDown={ ( event ) => {
						if ( event.key === 'Enter' ) {
							add();
						}
					} }
				/>
				<button
					type="button"
					className="ts-button ts-button--primary"
					onClick={ add }
				>
					{ tab === 'block'
						? __( 'Block IP', 'teksecurity' )
						: __( 'Allow IP', 'teksecurity' ) }
				</button>
			</div>

			<div className="ts-card">
				{ rows.length ? (
					rows.map( ( row ) => (
						<div className="ts-row" key={ row.id }>
							<span
								className="ts-mono"
								style={ { minWidth: 150 } }
							>
								{ row.ip }
							</span>
							<span className="ts-row__grow ts-row__desc">
								{ row.note || '—' }
							</span>
							<span className="ts-hint">
								{ sprintf(
									/* translators: %s: date the entry was added. */
									__( 'Added %s', 'teksecurity' ),
									new Date(
										row.createdAt.replace( ' ', 'T' )
									).toLocaleDateString( undefined, {
										month: 'short',
										day: 'numeric',
									} )
								) }
							</span>
							<button
								type="button"
								className="ts-link-button"
								onClick={ () => remove( row ) }
							>
								{ __( 'Remove', 'teksecurity' ) }
							</button>
						</div>
					) )
				) : (
					<div className="ts-inline-empty">
						{ __( 'No IPs in this list.', 'teksecurity' ) }
					</div>
				) }
			</div>
		</div>
	);
}
