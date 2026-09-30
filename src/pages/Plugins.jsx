/**
 * Plugin shields screen.
 */

import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import { useResource } from '../lib/useResource';
import {
	Chips,
	EmptyState,
	Loading,
	ModuleHeader,
	StatusPill,
	Switch,
	TitleRow,
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
	const { data, save, mutate } = useResource( '/plugins', {
		toast,
		refresh,
	} );
	const [ filter, setFilter ] = useState( 'all' );
	const [ busy, setBusy ] = useState( '' );

	if ( ! data ) {
		return <Loading />;
	}

	const toggleShield = ( plugin, shield ) =>
		mutate( () =>
			api.post( `/plugins/${ plugin.slug }/shield`, { shield } )
		);

	const updatePlugin = async ( plugin ) => {
		setBusy( plugin.slug );

		await mutate( () => api.post( `/plugins/${ plugin.slug }/update` ), {
			message: sprintf(
				/* translators: 1: plugin name, 2: version number. */
				__( '%1$s updated to %2$s', 'teksecurity' ),
				plugin.name,
				plugin.fixedIn
			),
		} );

		setBusy( '' );
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
				icon="plug"
				name={ __( 'Plugin exploit shields', 'teksecurity' ) }
				stopped={ data.vulnerable - data.exposed }
				enabled={ data.enabled }
				onToggle={ ( enabled ) =>
					save(
						{ enabled },
						enabled
							? __(
									'Plugin exploit shields turned on',
									'teksecurity'
							  )
							: __(
									'Plugin exploit shields turned off',
									'teksecurity'
							  )
					)
				}
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
									<TitleRow title={ plugin.name }>
										<span className="ts-hint">
											{ plugin.version }
										</span>
										<StatusPill
											tone={ tone }
											label={ label }
										/>
									</TitleRow>
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
									<div className="ts-actions">
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
												? __(
														'Updating…',
														'teksecurity'
												  )
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
						onClick={ () => setFilter( 'all' ) }
					>
						{ __( 'Show all plugins', 'teksecurity' ) }
					</button>
				</EmptyState>
			) }
		</div>
	);
}
