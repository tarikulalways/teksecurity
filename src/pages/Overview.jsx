/**
 * Dashboard screen.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import { dayLabel, timeAgo } from '../lib/format';
import {
	AttackTag,
	Card,
	Loading,
	StatusPill,
	toneStyle,
} from '../components/primitives';
import Icon from '../components/Icon';

/**
 * Build the banner that sits at the top of the dashboard.
 *
 * @param {Object}   data   Overview payload.
 * @param {Function} go     Navigate to a screen.
 * @param {Function} setFw  Change the firewall mode.
 * @return {Object} Banner descriptor.
 */
function buildBanner( data, go, setFw ) {
	const offModules = data.modules.filter( ( m ) => m.tone === 'bad' );

	if ( data.firewall.mode === 'off' ) {
		return {
			tone: 'bad',
			icon: 'ph-shield-slash',
			title: __( 'The firewall is off', 'teksecurity' ),
			desc: __(
				'Requests reach WordPress without inspection. Login, upload and rate-limit protection still run.',
				'teksecurity'
			),
			action: __( 'Turn on firewall', 'teksecurity' ),
			onAction: () => setFw( 'protect' ),
		};
	}

	if ( data.firewall.mode === 'learning' ) {
		return {
			tone: 'warn',
			icon: 'ph-shield-warning',
			title: __(
				'Learning mode: attacks are logged, not blocked',
				'teksecurity'
			),
			desc: __(
				'The firewall is recording what it would block so you can spot false alarms. Switch to Protect when you’re ready.',
				'teksecurity'
			),
			action: __( 'Start protecting', 'teksecurity' ),
			onAction: () => setFw( 'protect' ),
		};
	}

	if ( offModules.length ) {
		return {
			tone: 'warn',
			icon: 'ph-shield-warning',
			title: sprintf(
				/* translators: %d: number of protections that are off. */
				_n(
					'%d protection is off',
					'%d protections are off',
					offModules.length,
					'teksecurity'
				),
				offModules.length
			),
			desc: `${ offModules.map( ( m ) => m.name ).join( ', ' ) }.`,
			action: __( 'Review', 'teksecurity' ),
			onAction: () => go( offModules[ 0 ].page ),
		};
	}

	if ( data.exposed.length ) {
		return {
			tone: 'warn',
			icon: 'ph-shield-warning',
			title: sprintf(
				/* translators: %d: number of exposed plugins. */
				_n(
					'%d plugin is exposed',
					'%d plugins are exposed',
					data.exposed.length,
					'teksecurity'
				),
				data.exposed.length
			),
			desc: sprintf(
				/* translators: %s: comma separated plugin names. */
				__(
					'%s has a known vulnerability and no shield. Update or turn on its shield.',
					'teksecurity'
				),
				data.exposed.map( ( p ) => p.name ).join( ', ' )
			),
			action: __( 'Fix now', 'teksecurity' ),
			onAction: () => go( 'plugins' ),
		};
	}

	return {
		tone: 'ok',
		icon: 'ph-shield-check',
		title: sprintf(
			/* translators: %s: site host name. */
			__( '%s is protected', 'teksecurity' ),
			window.tekSecurityData.siteHost
		),
		desc: data.summary.lastBlockedAt
			? sprintf(
					/* translators: 1: number of protections, 2: relative time. */
					__(
						'All %1$d protections are running. Last attack blocked %2$s.',
						'teksecurity'
					),
					data.summary.modulesTotal,
					timeAgo( data.summary.lastBlockedAt )
			  )
			: sprintf(
					/* translators: %d: number of protections. */
					__(
						'All %d protections are running. Nothing has been blocked this week.',
						'teksecurity'
					),
					data.summary.modulesTotal
			  ),
		action: '',
	};
}

/**
 * The dashboard.
 *
 * @param {Object}   props           Component props.
 * @param {Function} props.go        Navigate to a screen.
 * @param {Function} props.openEvent Open the request drawer.
 * @param {Function} props.toast     Show a toast.
 * @return {JSX.Element} The screen.
 */
export default function Overview( { go, openEvent, toast } ) {
	const [ data, setData ] = useState( null );

	const load = () => api.get( '/overview' ).then( setData );

	useEffect( () => {
		load().catch( ( error ) => toast( error.message, 'error' ) );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [] );

	if ( ! data ) {
		return <Loading />;
	}

	const setFirewallMode = async ( mode ) => {
		try {
			await api.post( '/firewall', { mode } );
			await load();
			toast(
				mode === 'protect'
					? __( 'Firewall is now blocking attacks', 'teksecurity' )
					: __( 'Firewall mode updated', 'teksecurity' )
			);
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const banner = buildBanner( data, go, setFirewallMode );
	const bannerStyle = toneStyle( banner.tone );

	const maxDay = Math.max( 1, ...data.byDay.map( ( d ) => d.total ) );
	const maxType = Math.max( 1, ...data.breakdown.map( ( t ) => t.total ) );

	const stats = [
		{
			label: __( 'Blocked today', 'teksecurity' ),
			value: data.summary.blockedToday,
			sub: sprintf(
				/* translators: %d: number blocked yesterday. */
				__( '%d yesterday', 'teksecurity' ),
				data.summary.blockedYesterday
			),
		},
		{
			label: __( 'Blocked this week', 'teksecurity' ),
			value: data.summary.blockedWeek,
			sub: sprintf(
				/* translators: %d: number of logged-only requests. */
				__( '%d more logged only', 'teksecurity' ),
				data.summary.loggedWeek
			),
		},
		{
			label: __( 'Attacking IPs', 'teksecurity' ),
			value: data.summary.uniqueIps,
			sub: sprintf(
				/* translators: %d: number of addresses on the blocklist. */
				__( '%d on your blocklist', 'teksecurity' ),
				data.summary.blocklistedIps
			),
		},
		{
			label: __( 'Protections running', 'teksecurity' ),
			value: `${ data.summary.modulesRunning } / ${ data.summary.modulesTotal }`,
			sub:
				data.summary.modulesRunning === data.summary.modulesTotal
					? __( 'All active', 'teksecurity' )
					: sprintf(
							/* translators: %d: number of protections needing attention. */
							__( '%d need attention', 'teksecurity' ),
							data.summary.modulesTotal -
								data.summary.modulesRunning
					  ),
		},
	];

	return (
		<div className="ts-stack">
			<div
				className="ts-banner"
				style={ {
					background: bannerStyle.background,
					color: bannerStyle.color,
					borderColor: bannerStyle[ '--ts-dot' ],
				} }
			>
				<div className="ts-banner__icon">
					<Icon
						weight="fill"
						size={ 20 }
						name={ banner.icon.replace( 'ph-', '' ) }
					/>
				</div>
				<div className="ts-row__grow">
					<div className="ts-banner__title">{ banner.title }</div>
					<div className="ts-banner__desc">{ banner.desc }</div>
				</div>
				{ banner.action && (
					<button
						type="button"
						className="ts-button ts-button--primary"
						onClick={ banner.onAction }
					>
						{ banner.action }
					</button>
				) }
			</div>

			<div className="ts-stats">
				{ stats.map( ( stat ) => (
					<div className="ts-stat" key={ stat.label }>
						<div className="ts-stat__label">{ stat.label }</div>
						<div className="ts-stat__value">{ stat.value }</div>
						<div className="ts-stat__sub">{ stat.sub }</div>
					</div>
				) ) }
			</div>

			<div className="ts-split">
				<Card
					title={ __( 'Blocked requests', 'teksecurity' ) }
					meta={ __( 'Last 7 days', 'teksecurity' ) }
					flush
				>
					<div className="ts-chart">
						{ data.byDay.map( ( day, index ) => {
							const today = index === data.byDay.length - 1;

							return (
								<div className="ts-chart__col" key={ day.date }>
									<div className="ts-chart__value">
										{ day.total }
									</div>
									<div
										className={ `ts-chart__bar${
											today ? ' ts-chart__bar--today' : ''
										}` }
										style={ {
											height: `${ Math.round(
												( day.total / maxDay ) * 140
											) }px`,
										} }
									/>
									<div
										className={ `ts-chart__label${
											today
												? ' ts-chart__label--today'
												: ''
										}` }
									>
										{ dayLabel(
											day.date,
											index,
											data.byDay.length - 1
										) }
									</div>
								</div>
							);
						} ) }
					</div>
				</Card>

				<Card
					title={ __( 'Attack types', 'teksecurity' ) }
					action={
						<button
							type="button"
							className="ts-link-button"
							onClick={ () => go( 'traffic' ) }
						>
							{ __( 'View log', 'teksecurity' ) }
						</button>
					}
					flush
				>
					{ data.breakdown.length ? (
						<div className="ts-breakdown">
							{ data.breakdown.map( ( item ) => (
								<button
									type="button"
									key={ item.type }
									className="ts-breakdown__item"
									onClick={ () =>
										go( 'traffic', { type: item.type } )
									}
								>
									<span>{ item.label }</span>
									<span className="ts-breakdown__track">
										<span
											className="ts-breakdown__fill"
											style={ {
												width: `${ Math.round(
													( item.total / maxType ) *
														100
												) }%`,
											} }
										/>
									</span>
									<span className="ts-breakdown__count">
										{ item.total }
									</span>
								</button>
							) ) }
						</div>
					) : (
						<div className="ts-inline-empty">
							{ __(
								'Nothing has been blocked in the last 7 days.',
								'teksecurity'
							) }
						</div>
					) }
				</Card>
			</div>

			<div className="ts-split">
				<Card
					title={ __( 'Latest attacks', 'teksecurity' ) }
					action={
						<button
							type="button"
							className="ts-link-button"
							onClick={ () => go( 'traffic' ) }
						>
							{ __( 'See all', 'teksecurity' ) }
						</button>
					}
					flush
				>
					{ data.recent.length ? (
						data.recent.map( ( event ) => (
							<button
								type="button"
								key={ event.id }
								className="ts-list-button"
								onClick={ () => openEvent( event.id ) }
							>
								<AttackTag type={ event.type } />
								<span className="ts-list-button__path">
									{ event.method } { event.path }
								</span>
								<span className="ts-list-button__time">
									{ timeAgo( event.createdAt ) }
								</span>
								<Icon
									name="caret-right"
									className="ts-list-button__chevron"
								/>
							</button>
						) )
					) : (
						<div className="ts-inline-empty">
							{ __( 'No attacks recorded yet.', 'teksecurity' ) }
						</div>
					) }
				</Card>

				<Card title={ __( 'Protections', 'teksecurity' ) } flush>
					{ data.modules.map( ( module ) => (
						<button
							type="button"
							key={ module.key }
							className="ts-list-button"
							onClick={ () => go( module.page ) }
						>
							<Icon
								name={ module.icon.replace( 'ph-', '' ) }
								size={ 16 }
							/>
							<span className="ts-row__grow">
								{ module.name }
							</span>
							<StatusPill
								tone={ module.tone }
								label={ module.status }
							/>
						</button>
					) ) }
				</Card>
			</div>
		</div>
	);
}
