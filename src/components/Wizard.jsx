/**
 * The four-step setup wizard.
 */

import { Fragment, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import { api, boot } from '../lib/api';
import { RadioCards, Segmented } from './primitives';
import Icon from './Icon';

/**
 * Walk the site owner through the four choices that matter, then turn
 * protection on.
 *
 * @param {Object}   props          Component props.
 * @param {Object}   props.initial  Current settings to pre-fill the answers.
 * @param {Function} props.onFinish Called with the saved settings.
 * @param {Function} props.toast    Show a toast.
 * @return {JSX.Element} The wizard.
 */
export default function Wizard( { initial, onFinish, toast } ) {
	const [ step, setStep ] = useState( 0 );
	const [ touched, setTouched ] = useState( false );
	const [ busy, setBusy ] = useState( false );
	const [ answers, setAnswers ] = useState( {
		mode: initial.mode || 'simple',
		proxy: initial.proxy || 'direct',
		level: initial.level === 'learning' ? 'learning' : 'protect',
		email: initial.email || boot.user.email,
		alerts: initial.alerts || 'critical',
	} );

	const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test( answers.email );
	const emailError = touched && ! emailValid && answers.alerts !== 'off';

	const set = ( values ) => setAnswers( { ...answers, ...values } );

	const steps = [
		{
			title: __( 'Welcome to TekSecurity', 'teksecurity' ),
			desc: __(
				'Four quick questions and your firewall is running. You can change every answer later in Settings.',
				'teksecurity'
			),
			field: 'mode',
			options: [
				{
					key: 'simple',
					label: __( 'Simple view', 'teksecurity' ),
					desc: __(
						'Plain-language screens with recommended settings. Best for site owners.',
						'teksecurity'
					),
					recommended: true,
				},
				{
					key: 'advanced',
					label: __( 'Advanced view', 'teksecurity' ),
					desc: __(
						'Rule IDs, payloads, per-rule modes and custom limits. For developers and agencies.',
						'teksecurity'
					),
				},
			],
		},
		{
			title: __( 'How does traffic reach your site?', 'teksecurity' ),
			desc: __(
				'This lets TekSecurity see each visitor’s real IP, so it blocks attackers and not your CDN.',
				'teksecurity'
			),
			field: 'proxy',
			options: [
				{
					key: 'direct',
					label: __( 'Directly to my host', 'teksecurity' ),
					desc: __(
						'No CDN or proxy in front of WordPress.',
						'teksecurity'
					),
					recommended: true,
				},
				{
					key: 'cloudflare',
					label: __( 'Through Cloudflare', 'teksecurity' ),
					desc: __(
						'Reads the visitor IP Cloudflare passes along.',
						'teksecurity'
					),
				},
				{
					key: 'proxy',
					label: __( 'Through another proxy or CDN', 'teksecurity' ),
					desc: __(
						'Reads the X-Forwarded-For header.',
						'teksecurity'
					),
				},
			],
		},
		{
			title: __( 'Start blocking now?', 'teksecurity' ),
			desc: __(
				'Learning mode is useful if your site runs custom code that could look unusual to a firewall.',
				'teksecurity'
			),
			field: 'level',
			options: [
				{
					key: 'protect',
					label: __( 'Protect now', 'teksecurity' ),
					desc: __(
						'Attacks are blocked from the first request.',
						'teksecurity'
					),
					recommended: true,
				},
				{
					key: 'learning',
					label: __( 'Learn for 7 days first', 'teksecurity' ),
					desc: __(
						'Attacks are logged but not blocked, so you can review false alarms.',
						'teksecurity'
					),
				},
			],
		},
		{
			title: __( 'Where should alerts go?', 'teksecurity' ),
			desc: __(
				'We email you when something needs your attention, like an exposed plugin or a large attack.',
				'teksecurity'
			),
		},
		{
			title: __( 'You’re protected', 'teksecurity' ),
			desc: sprintf(
				/* translators: %s: site host name. */
				__(
					'TekSecurity is now inspecting every request to %s.',
					'teksecurity'
				),
				boot.siteHost
			),
		},
	];

	const current = steps[ step ];
	const isDone = step === 4;

	const finish = async ( useDefaults ) => {
		const payload = useDefaults
			? {
					mode: 'simple',
					proxy: 'direct',
					level: 'protect',
					email: boot.user.email,
					alerts: 'critical',
			  }
			: answers;

		setBusy( true );

		try {
			const settings = await api.post( '/onboarding', payload );
			onFinish( settings );
			toast(
				payload.level === 'learning'
					? __( 'Learning mode is on', 'teksecurity' )
					: __( 'Your site is protected', 'teksecurity' )
			);
		} catch ( error ) {
			toast( error.message, 'error' );
		} finally {
			setBusy( false );
		}
	};

	const next = () => {
		if ( step === 3 && answers.alerts !== 'off' && ! emailValid ) {
			setTouched( true );
			return;
		}

		if ( isDone ) {
			finish( false );
			return;
		}

		setStep( step + 1 );
	};

	const proxyLabels = {
		direct: __( 'Direct connection', 'teksecurity' ),
		cloudflare: __( 'Cloudflare', 'teksecurity' ),
		proxy: __( 'Other proxy or CDN', 'teksecurity' ),
	};

	const summary = [
		[
			__( 'View', 'teksecurity' ),
			answers.mode === 'simple'
				? __( 'Simple', 'teksecurity' )
				: __( 'Advanced', 'teksecurity' ),
		],
		[ __( 'Visitor IP', 'teksecurity' ), proxyLabels[ answers.proxy ] ],
		[
			__( 'Firewall', 'teksecurity' ),
			answers.level === 'protect'
				? __( 'Protecting', 'teksecurity' )
				: __( 'Learning for 7 days', 'teksecurity' ),
		],
		[
			__( 'Alerts', 'teksecurity' ),
			answers.alerts === 'off'
				? __( 'Off', 'teksecurity' )
				: `${
						answers.alerts === 'critical'
							? __( 'Critical attacks', 'teksecurity' )
							: __( 'Every block', 'teksecurity' )
				  } → ${ answers.email }`,
		],
	];

	return (
		<div className="ts-wizard">
			<div
				className="ts-wizard__panel"
				role="dialog"
				aria-modal="true"
				aria-label={ current.title }
			>
				<div>
					<div className="ts-wizard__mark">
						<Icon name="shield-check" weight="fill" />
					</div>
					{ ! isDone && (
						<div className="ts-wizard__step">
							{ sprintf(
								/* translators: %d: current step number. */
								__( 'Step %d of 4', 'teksecurity' ),
								step + 1
							) }
						</div>
					) }
					<h2 className="ts-wizard__title">{ current.title }</h2>
					<p className="ts-wizard__desc">{ current.desc }</p>
				</div>

				{ ! isDone && (
					<div className="ts-wizard__progress">
						{ [ 0, 1, 2, 3 ].map( ( index ) => (
							<span
								key={ index }
								className={ index <= step ? 'is-done' : '' }
							/>
						) ) }
					</div>
				) }

				{ current.options && (
					<RadioCards
						value={ answers[ current.field ] }
						options={ current.options }
						onChange={ ( value ) =>
							set( { [ current.field ]: value } )
						}
					/>
				) }

				{ step === 3 && (
					<div className="ts-stack">
						<label className="ts-field">
							{ __( 'Alert email', 'teksecurity' ) }
							<input
								type="email"
								className={ `ts-input${
									emailError ? ' ts-input--error' : ''
								}` }
								value={ answers.email }
								placeholder="you@example.com"
								onChange={ ( event ) =>
									set( { email: event.target.value } )
								}
							/>
							<span
								className={ `ts-hint${
									emailError ? ' ts-hint--error' : ''
								}` }
							>
								{ emailError
									? __(
											'Enter a valid email address, or choose Nothing.',
											'teksecurity'
									  )
									: __(
											'Usually the site administrator’s address.',
											'teksecurity'
									  ) }
							</span>
						</label>

						<div>
							<div
								className="ts-field"
								style={ { marginBottom: 6 } }
							>
								{ __( 'Send an email for', 'teksecurity' ) }
							</div>
							<Segmented
								label={ __( 'Alert level', 'teksecurity' ) }
								value={ answers.alerts }
								options={ [
									[
										'critical',
										__( 'Critical attacks', 'teksecurity' ),
									],
									[
										'all',
										__( 'Every block', 'teksecurity' ),
									],
									[ 'off', __( 'Nothing', 'teksecurity' ) ],
								] }
								onChange={ ( alerts ) => set( { alerts } ) }
							/>
						</div>
					</div>
				) }

				{ isDone && (
					<dl className="ts-kv">
						{ summary.map( ( [ key, value ] ) => (
							<Fragment key={ key }>
								<dt>{ key }</dt>
								<dd>{ value }</dd>
							</Fragment>
						) ) }
					</dl>
				) }

				<div className="ts-wizard__foot">
					{ step > 0 && step < 4 && (
						<button
							type="button"
							className="ts-button"
							onClick={ () => setStep( step - 1 ) }
						>
							{ __( 'Back', 'teksecurity' ) }
						</button>
					) }
					<button
						type="button"
						className="ts-button ts-button--primary"
						disabled={ busy }
						onClick={ next }
					>
						{ isDone
							? __( 'Go to dashboard', 'teksecurity' )
							: step === 3
							? __( 'Turn on protection', 'teksecurity' )
							: __( 'Continue', 'teksecurity' ) }
					</button>
				</div>

				{ ! isDone && (
					<button
						type="button"
						className="ts-wizard__skip"
						disabled={ busy }
						onClick={ () => finish( true ) }
					>
						{ __(
							'Skip setup and use recommended settings',
							'teksecurity'
						) }
					</button>
				) }
			</div>
		</div>
	);
}
