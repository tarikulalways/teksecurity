/**
 * Firewall screen.
 */

import { __, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import { useResource } from '../lib/useResource';
import {
	Card,
	Loading,
	RadioCards,
	Segmented,
	Switch,
} from '../components/primitives';
import Icon from '../components/Icon';

/**
 * Firewall mode, per-rule switches and rule exclusions.
 *
 * @param {Object}   props         Component props.
 * @param {boolean}  props.isAdv   Whether advanced view is on.
 * @param {Function} props.toast   Show a toast.
 * @param {Function} props.refresh Refresh the shell's badges.
 * @return {JSX.Element} The screen.
 */
export default function Firewall( { isAdv, toast, refresh } ) {
	const { data, save, mutate } = useResource( '/firewall', {
		toast,
		refresh,
	} );

	if ( ! data ) {
		return <Loading />;
	}

	const modeMessages = {
		protect: __( 'Firewall is now blocking attacks', 'teksecurity' ),
		learning: __( 'Learning mode is on', 'teksecurity' ),
		off: __( 'Firewall turned off', 'teksecurity' ),
	};

	return (
		<div className="ts-stack">
			<Card title={ __( 'Firewall mode', 'teksecurity' ) }>
				<p className="ts-row__desc" style={ { marginBottom: 12 } }>
					{ __(
						'Applies to every firewall rule on this page.',
						'teksecurity'
					) }
				</p>
				<RadioCards
					value={ data.mode }
					onChange={ ( mode ) =>
						save( { mode }, modeMessages[ mode ] )
					}
					options={ [
						{
							key: 'protect',
							label: __( 'Protect', 'teksecurity' ),
							desc: __(
								'Blocks attacks as they happen.',
								'teksecurity'
							),
						},
						{
							key: 'learning',
							label: __( 'Learning', 'teksecurity' ),
							desc: __(
								'Logs what would be blocked. Use for a few days after big site changes.',
								'teksecurity'
							),
						},
						{
							key: 'off',
							label: __( 'Off', 'teksecurity' ),
							desc: __(
								'No inspection. Not recommended.',
								'teksecurity'
							),
						},
					] }
				/>
			</Card>

			<Card
				title={ __( 'Firewall rules', 'teksecurity' ) }
				meta={
					isAdv
						? sprintf(
								/* translators: %d: number of signatures. */
								__( '%d signatures', 'teksecurity' ),
								data.ruleTotal
						  )
						: null
				}
				flush
			>
				{ data.modules.map( ( module ) => (
					<div
						className={ `ts-row${
							module.on ? '' : ' ts-row--dim'
						}` }
						key={ module.key }
					>
						<div className="ts-row__icon">
							<Icon
								name={ module.icon.replace( 'ph-', '' ) }
								size={ 17 }
							/>
						</div>
						<div className="ts-row__grow">
							<div className="ts-row__title">{ module.name }</div>
							<div className="ts-row__desc">{ module.desc }</div>
							<div className="ts-row__meta">
								{ isAdv
									? sprintf(
											/* translators: 1: rule count, 2: match count. */
											__(
												'%1$d rules · %2$d matches this week',
												'teksecurity'
											),
											module.rules,
											module.matches
									  )
									: sprintf(
											/* translators: %d: number of attempts stopped. */
											__(
												'%d attempts stopped this week',
												'teksecurity'
											),
											module.matches
									  ) }
							</div>
						</div>
						{ isAdv && (
							<Segmented
								label={ module.name }
								value={ module.action }
								options={ [
									[ 'block', __( 'Block', 'teksecurity' ) ],
									[ 'log', __( 'Log only', 'teksecurity' ) ],
								] }
								onChange={ ( act ) =>
									save( {
										modules: { [ module.key ]: { act } },
									} )
								}
							/>
						) }
						<Switch
							label={ module.name }
							checked={ module.on }
							onChange={ ( on ) =>
								save( { modules: { [ module.key ]: { on } } } )
							}
						/>
					</div>
				) ) }
			</Card>

			{ isAdv && (
				<Card title={ __( 'Rule exclusions', 'teksecurity' ) } flush>
					<div
						className="ts-row__desc"
						style={ { padding: '12px 16px 0' } }
					>
						{ __(
							'Rules skipped on specific paths. Add one from a request in the traffic log.',
							'teksecurity'
						) }
					</div>
					{ data.exclusions.length ? (
						data.exclusions.map( ( row ) => (
							<div className="ts-row" key={ row.id }>
								<span className="ts-mono">{ row.ruleId }</span>
								<span className="ts-mono ts-row__grow">
									{ row.path }
								</span>
								<button
									type="button"
									className="ts-link-button"
									onClick={ () =>
										mutate(
											() =>
												api.del(
													`/firewall/exclusions/${ row.id }`
												),
											{
												merge: true,
												message: __(
													'Exclusion removed',
													'teksecurity'
												),
											}
										)
									}
								>
									{ __( 'Remove', 'teksecurity' ) }
								</button>
							</div>
						) )
					) : (
						<div className="ts-inline-empty">
							{ __(
								'No exclusions. Every rule runs on every path.',
								'teksecurity'
							) }
						</div>
					) }
				</Card>
			) }
		</div>
	);
}
