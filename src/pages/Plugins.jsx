/**
 * Plugin shields screen.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import {
	Chips,
	EmptyState,
	Loading,
	ModuleHeader,
	StatusPill,
	Switch,
} from '../components/primitives';
import Icon from '../components/Icon';

/**
 * Installed plugins with their vulnerability state and virtual patches.
 *
 * @param {Object}   props         Component props.
 * @param {boolean}  props.isAdv   Whether advanced view is on.
 * @param {Function} props.toast   Show a toast.
 * @param {Function} props.refresh Refresh the shell's badges.
 * @return {JSX.Element} The screen.
 */
export default function Plugins( { isAdv, toast, refresh } ) {
	const [ data, setData ] = useState( null );
	const [ filter, setFilter ] = useState( 'all' );
	const [ busy, setBusy ] = useState( '' );

	useEffect( () => {
		api.get( '/plugins' )
			.then( setData )
			.catch( ( error ) => toast( error.message, 'error' ) );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [] );

	if ( ! data ) {
		return <Loading />;
	}

	const apply = ( next, message ) => {
		setData( next );
		refresh();

		if ( message ) {
			toast( message );
		}
	};

	const toggleModule = async ( enabled ) => {
		try {
			apply(
				await api.post( '/plugins', { enabled } ),
				enabled
					? __( 'Plugin exploit shields turned on', 'teksecurity' )
					: __( 'Plugin exploit shields turned off', 'teksecurity' )
			);
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const toggleShield = async ( plugin, shield ) => {
		try {
			apply( await api.post( `/plugins/${ plugin.slug }/shield`, { shield } ) );
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const updatePlugin = async ( plugin ) => {
		setBusy( plugin.slug );

		try {
			apply(
				await api.post( `/plugins/${ plugin.slug }/update` ),
				sprintf(
					/* translators: 1: plugin name, 2: version number. */
					__( '%1$s updated to %2$s', 'teksecurity' ),
					plugin.name,
					plugin.fixedIn
				)
			);
		} catch ( error ) {
			toast( error.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const rows = data.plugins.filter( ( plugin ) => {
		if ( filter === 'vuln' ) {
			return plugin.vulnerable;
		}
		if ( filter === 'ok' ) {
			return ! plugin.vulnerable;
		}
		return true;
	} );

	return (
		<div className="ts-stack">
			<ModuleHeader
				icon="ph-plug"
				name={ __( 'Plugin exploit shields', 'teksecurity' ) }
				status={
					data.enabled
						? __( 'Active', 'teksecurity' )
						: __( 'Off', 'teksecurity' )
				}
				tone={ data.enabled ? 'ok' : 'bad' }
				stopped={ data.vulnerable - data.exposed }
				enabled={ data.enabled }
				onToggle={ toggleModule }
			/>

			<Chips
				value={ filter }
				onChange={ setFilter }
				options={ [
					[
						'all',
						sprintf(
							/* translators: %d: total plugin count. */
							__( 'All plugins (%d)', 'teksecurity' ),
							data.plugins.length
						),
					],
					[
						'vuln',
						sprintf(
							/* translators: %d: vulnerable plugin count. */
							__( 'Vulnerable (%d)', 'teksecurity' ),
							data.vulnerable
						),
					],
					[
						'ok',
						sprintf(
							/* translators: %d: up-to-date plugin count. */
							__( 'Up to date (%d)', 'teksecurity' ),
							data.plugins.length - data.vulnerable
						),
					],
				] }
			/>

			{ rows.length ? (
				<div className="ts-card">
					{ rows.map( ( plugin ) => {
						const shielded =
							plugin.vulnerable && plugin.shield && data.enabled;
						const tone = ! plugin.vulnerable
							? 'ok'
							: shielded
							? 'info'
							: 'bad';
						const label = ! plugin.vulnerable
							? __( 'No known issues', 'teksecurity' )
							: shielded
							? __( 'Shielded', 'teksecurity' )
							: __( 'Exposed', 'teksecurity' );

						return (
							<div className="ts-row" key={ plugin.slug }>
								<div className="ts-row__icon">
									<Icon name="plug" />
								</div>
								<div className="ts-row__grow">
									<div
										style={ {
											display: 'flex',
											alignItems: 'center',
											gap: 8,
											flexWrap: 'wrap',
										} }
									>
										<span className="ts-row__title">
											{ plugin.name }
										</span>
										<span className="ts-hint">
											{ plugin.version }
										</span>
										<StatusPill tone={ tone } label={ label } />
									</div>
									{ plugin.vulnerable && (
										<div className="ts-row__desc">
											{ sprintf(
												/* translators: 1: severity, 2: issue, 3: fixed version. */
												__(
													'%1$s · %2$s. Fixed in %3$s.',
													'teksecurity'
												),
												plugin.severity,
												plugin.issue,
												plugin.fixedIn
											) }
										</div>
									) }
									{ plugin.vulnerable && isAdv && (
										<div className="ts-row__meta ts-mono">
											{ sprintf(
												/* translators: %s: virtual patch identifier. */
												__(
													'Virtual patch %s',
													'teksecurity'
												),
												plugin.patchId
											) }
										</div>
									) }
								</div>

								{ plugin.vulnerable && (
									<div
										style={ {
											display: 'flex',
											alignItems: 'center',
											gap: 10,
										} }
									>
										<span className="ts-hint">
											{ __( 'Shield', 'teksecurity' ) }
										</span>
										<Switch
											label={ sprintf(
												/* translators: %s: plugin name. */
												__(
													'Shield for %s',
													'teksecurity'
												),
												plugin.name
											) }
											checked={ plugin.shield }
											onChange={ ( shield ) =>
												toggleShield( plugin, shield )
											}
										/>
										<button
											type="button"
											className="ts-button ts-button--primary ts-button--small"
											disabled={ busy === plugin.slug }
											onClick={ () =>
												updatePlugin( plugin )
											}
										>
											{ busy === plugin.slug
												? __( 'Updating…', 'teksecurity' )
												: sprintf(
														/* translators: %s: version number. */
														__(
															'Update to %s',
															'teksecurity'
														),
														plugin.fixedIn
												  ) }
										</button>
									</div>
								) }
							</div>
						);
					} ) }
				</div>
			) : (
				<EmptyState
					icon="ph-check-circle"
					title={ __( 'Nothing needs attention', 'teksecurity' ) }
					desc={ __(
						'Every installed plugin is free of known vulnerabilities.',
						'teksecurity'
					) }
				>
					<button
						type="button"
						className="ts-button"
						style={ { marginTop: 10 } }
						onClick={ () => setFilter( 'all' ) }
					>
						{ __( 'Show all plugins', 'teksecurity' ) }
					</button>
				</EmptyState>
			) }
		</div>
	);
}
