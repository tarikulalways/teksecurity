/**
 * Rate limiting screen.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import {
	Card,
	Loading,
	ModuleHeader,
	RadioCards,
	Segmented,
	SettingRow,
	Switch,
} from '../components/primitives';

/**
 * Per-IP request limits.
 *
 * @param {Object}   props         Component props.
 * @param {boolean}  props.isAdv   Whether advanced view is on.
 * @param {Function} props.toast   Show a toast.
 * @param {Function} props.refresh Refresh the shell's badges.
 * @return {JSX.Element} The screen.
 */
export default function RateLimit( { isAdv, toast, refresh } ) {
	const [ data, setData ] = useState( null );

	useEffect( () => {
		api.get( '/ratelimit' )
			.then( setData )
			.catch( ( error ) => toast( error.message, 'error' ) );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [] );

	if ( ! data ) {
		return <Loading />;
	}

	const save = async ( payload, message ) => {
		try {
			setData( await api.post( '/ratelimit', payload ) );
			refresh();

			if ( message ) {
				toast( message );
			}
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const patchRule = ( key, patch ) =>
		save( { rules: [ { key, ...patch } ] } );

	return (
		<div className="ts-stack">
			<ModuleHeader
				icon="ph-gauge"
				name={ __( 'Rate limiting', 'teksecurity' ) }
				status={
					data.enabled
						? __( 'Active', 'teksecurity' )
						: __( 'Off', 'teksecurity' )
				}
				tone={ data.enabled ? 'ok' : 'bad' }
				stopped={ data.stopped }
				enabled={ data.enabled }
				onToggle={ ( enabled ) =>
					save(
						{ enabled },
						enabled
							? __( 'Rate limiting turned on', 'teksecurity' )
							: __( 'Rate limiting turned off', 'teksecurity' )
					)
				}
			/>

			<Card title={ __( 'Strictness', 'teksecurity' ) }>
				<p className="ts-row__desc" style={ { marginBottom: 12 } }>
					{ data.preset === 'custom'
						? __(
								'Custom limits. Pick a level to reset them.',
								'teksecurity'
						  )
						: __(
								'Sets every limit below at once.',
								'teksecurity'
						  ) }
				</p>
				<RadioCards
					value={ data.preset }
					onChange={ ( preset ) => save( { preset } ) }
					options={ [
						{
							key: 'relaxed',
							label: __( 'Relaxed', 'teksecurity' ),
							desc: __(
								'For busy stores and sites with apps using the REST API.',
								'teksecurity'
							),
						},
						{
							key: 'balanced',
							label: __( 'Balanced', 'teksecurity' ),
							desc: __( 'Right for most sites.', 'teksecurity' ),
							recommended: true,
						},
						{
							key: 'strict',
							label: __( 'Strict', 'teksecurity' ),
							desc: __(
								'For sites under active attack.',
								'teksecurity'
							),
						},
					] }
				/>
			</Card>

			<Card title={ __( 'Limits per IP', 'teksecurity' ) } flush>
				{ data.rules.map( ( rule ) => {
					const editable = isAdv && rule.limit > 0 && rule.on;

					return (
						<div className="ts-row" key={ rule.key }>
							<div className="ts-row__grow">
								<div className="ts-row__title">
									{ rule.name }
								</div>
								<div className="ts-row__desc ts-mono">
									{ rule.path }
								</div>
							</div>

							{ editable ? (
								<div
									style={ {
										display: 'flex',
										alignItems: 'center',
										gap: 6,
									} }
								>
									<input
										type="number"
										min="1"
										className="ts-input"
										style={ { width: 86 } }
										value={ rule.limit }
										aria-label={ sprintf(
											/* translators: %s: rule name. */
											__(
												'Requests per minute for %s',
												'teksecurity'
											),
											rule.name
										) }
										onChange={ ( event ) =>
											patchRule( rule.key, {
												limit: Math.max(
													1,
													parseInt(
														event.target.value,
														10
													) || 1
												),
											} )
										}
									/>
									<span className="ts-hint">
										{ __( 'per minute', 'teksecurity' ) }
									</span>
								</div>
							) : (
								<span
									className="ts-hint"
									style={ { fontSize: 13 } }
								>
									{ ! rule.on
										? __( 'No limit', 'teksecurity' )
										: rule.limit
										? sprintf(
												/* translators: %d: requests per minute. */
												__( '%d / min', 'teksecurity' ),
												rule.limit
										  )
										: __(
												'Blocked completely',
												'teksecurity'
										  ) }
								</span>
							) }

							<Switch
								label={ rule.name }
								checked={ rule.on }
								onChange={ ( on ) =>
									patchRule( rule.key, { on } )
								}
							/>
						</div>
					);
				} ) }

				<SettingRow
					title={ __( 'When a limit is reached', 'teksecurity' ) }
				>
					<Segmented
						label={ __(
							'Action when a limit is reached',
							'teksecurity'
						) }
						value={ data.action }
						options={ [
							[
								'throttle',
								__( 'Slow down (429)', 'teksecurity' ),
							],
							[ 'block', __( 'Block for 10 min', 'teksecurity' ) ],
						] }
						onChange={ ( action ) => save( { action } ) }
					/>
				</SettingRow>

				<SettingRow
					title={ __(
						'Don’t limit logged-in administrators',
						'teksecurity'
					) }
					desc={ __(
						'Keeps bulk edits and imports working.',
						'teksecurity'
					) }
				>
					<Switch
						label={ __(
							'Skip limits for administrators',
							'teksecurity'
						) }
						checked={ data.bypass }
						onChange={ ( bypass ) => save( { bypass } ) }
					/>
				</SettingRow>
			</Card>
		</div>
	);
}
