/**
 * Small presentational pieces shared by every screen.
 */

import { __ } from '@wordpress/i18n';
import Icon from './Icon';

/**
 * Colour triplet for a status tone.
 *
 * @param {string} tone ok|warn|info|bad.
 * @return {Object} CSS custom properties for the pill.
 */
export function toneStyle( tone ) {
	const key = [ 'ok', 'warn', 'info', 'bad' ].includes( tone ) ? tone : 'ok';

	return {
		background: `var(--ts-${ key }-bg)`,
		color: `var(--ts-${ key }-fg)`,
		'--ts-dot': `var(--ts-${ key }-dot)`,
	};
}

/**
 * A status pill with a leading dot.
 *
 * @param {Object} props       Component props.
 * @param {string} props.tone  ok|warn|info|bad.
 * @param {string} props.label Text.
 * @return {JSX.Element} The pill.
 */
export function StatusPill( { tone, label } ) {
	const style = toneStyle( tone );

	return (
		<span className="ts-pill" style={ style }>
			<span
				className="ts-pill__dot"
				style={ { background: style[ '--ts-dot' ] } }
			/>
			{ label }
		</span>
	);
}

/**
 * An on/off switch.
 *
 * @param {Object}   props          Component props.
 * @param {boolean}  props.checked  Current state.
 * @param {Function} props.onChange Called with the next state.
 * @param {string}   props.label    Accessible label.
 * @param {boolean}  props.disabled Whether the switch is locked.
 * @return {JSX.Element} The switch.
 */
export function Switch( { checked, onChange, label, disabled = false } ) {
	return (
		<button
			type="button"
			role="switch"
			aria-checked={ checked }
			aria-label={ label }
			disabled={ disabled }
			className={ `ts-switch${ checked ? ' ts-switch--on' : '' }` }
			onClick={ () => onChange( ! checked ) }
		>
			<span className="ts-switch__knob" />
		</button>
	);
}

/**
 * A segmented control.
 *
 * @param {Object}   props          Component props.
 * @param {Array}    props.options  [ value, label ] pairs.
 * @param {string}   props.value    Selected value.
 * @param {Function} props.onChange Called with the next value.
 * @param {string}   props.label    Accessible group label.
 * @return {JSX.Element} The control.
 */
export function Segmented( { options, value, onChange, label } ) {
	return (
		<div className="ts-segmented" role="group" aria-label={ label }>
			{ options.map( ( [ key, text ] ) => (
				<button
					key={ key }
					type="button"
					aria-pressed={ value === key }
					className={ `ts-segmented__option${
						value === key ? ' ts-segmented__option--active' : ''
					}` }
					onClick={ () => onChange( key ) }
				>
					{ text }
				</button>
			) ) }
		</div>
	);
}

/**
 * A filter chip row.
 *
 * @param {Object}   props          Component props.
 * @param {Array}    props.options  [ value, label ] pairs.
 * @param {string}   props.value    Selected value.
 * @param {Function} props.onChange Called with the next value.
 * @return {JSX.Element} The chips.
 */
export function Chips( { options, value, onChange } ) {
	return (
		<div className="ts-chips">
			{ options.map( ( [ key, text ] ) => (
				<button
					key={ key }
					type="button"
					aria-pressed={ value === key }
					className={ `ts-chip${
						value === key ? ' ts-chip--active' : ''
					}` }
					onClick={ () => onChange( key ) }
				>
					{ text }
				</button>
			) ) }
		</div>
	);
}

/**
 * A stack of radio cards.
 *
 * @param {Object}   props          Component props.
 * @param {Array}    props.options  Objects with key, label, desc and recommended.
 * @param {string}   props.value    Selected key.
 * @param {Function} props.onChange Called with the next key.
 * @return {JSX.Element} The radio group.
 */
export function RadioCards( { options, value, onChange } ) {
	return (
		<div className="ts-radios" role="radiogroup">
			{ options.map( ( option ) => {
				const active = value === option.key;

				return (
					<button
						key={ option.key }
						type="button"
						role="radio"
						aria-checked={ active }
						className={ `ts-radio${
							active ? ' ts-radio--active' : ''
						}` }
						onClick={ () => onChange( option.key ) }
					>
						<span className="ts-radio__ring">
							<Icon name="check" weight="bold" />
						</span>
						<span>
							<span className="ts-radio__label">
								{ option.label }
								{ option.recommended && (
									<span className="ts-badge-rec">
										{ __(
											'Recommended',
											'teksecurity'
										) }
									</span>
								) }
							</span>
							<span className="ts-radio__desc">
								{ option.desc }
							</span>
						</span>
					</button>
				);
			} ) }
		</div>
	);
}

/**
 * A card with an optional header.
 *
 * @param {Object}      props          Component props.
 * @param {string}      props.title    Header title.
 * @param {JSX.Element} props.action   Header right-hand slot.
 * @param {string}      props.meta     Header right-hand text.
 * @param {boolean}     props.flush    Remove the body padding.
 * @param {JSX.Element} props.children Body.
 * @return {JSX.Element} The card.
 */
export function Card( { title, action, meta, flush = false, children } ) {
	return (
		<section className="ts-card">
			{ ( title || action || meta ) && (
				<header className="ts-card__head">
					<div className="ts-card__title">{ title }</div>
					{ action }
					{ meta && <div className="ts-card__meta">{ meta }</div> }
				</header>
			) }
			<div
				className={ `ts-card__body${
					flush ? ' ts-card__body--flush' : ''
				}` }
			>
				{ children }
			</div>
		</section>
	);
}

/**
 * A settings row with a title, description and a control.
 *
 * @param {Object}      props          Component props.
 * @param {string}      props.title    Row title.
 * @param {string}      props.desc     Supporting text.
 * @param {JSX.Element} props.children The control.
 * @return {JSX.Element} The row.
 */
export function SettingRow( { title, desc, children } ) {
	return (
		<div className="ts-row">
			<div className="ts-row__grow">
				<div className="ts-row__title">{ title }</div>
				{ desc && <div className="ts-row__desc">{ desc }</div> }
			</div>
			{ children }
		</div>
	);
}

/**
 * A full-width empty state.
 *
 * @param {Object}      props          Component props.
 * @param {string}      props.icon     Phosphor icon class.
 * @param {string}      props.title    Headline.
 * @param {string}      props.desc     Supporting text.
 * @param {JSX.Element} props.children Optional action.
 * @return {JSX.Element} The empty state.
 */
export function EmptyState( { icon, title, desc, children } ) {
	return (
		<div className="ts-empty">
			<div className="ts-empty__icon">
				<Icon name={ icon.replace( 'ph-', '' ) } />
			</div>
			<div className="ts-empty__title">{ title }</div>
			{ desc && <div className="ts-empty__desc">{ desc }</div> }
			{ children }
		</div>
	);
}

/**
 * A loading placeholder.
 *
 * @return {JSX.Element} The spinner row.
 */
export function Loading() {
	return (
		<div className="ts-loading">
			<span className="ts-spinner" />
			{ __( 'Loading…', 'teksecurity' ) }
		</div>
	);
}

/**
 * The module header shown on the four single-module screens.
 *
 * @param {Object}   props          Component props.
 * @param {string}   props.icon     Phosphor icon class.
 * @param {string}   props.name     Module name.
 * @param {string}   props.status   Status label.
 * @param {string}   props.tone     Status tone.
 * @param {number}   props.stopped  Attempts stopped this week.
 * @param {boolean}  props.enabled  Whether the module is on.
 * @param {Function} props.onToggle Called with the next state.
 * @return {JSX.Element} The header card.
 */
export function ModuleHeader( {
	icon,
	name,
	status,
	tone,
	stopped,
	enabled,
	onToggle,
} ) {
	return (
		<section className="ts-card">
			<div className="ts-row" style={ { opacity: enabled ? 1 : 0.6 } }>
				<div className="ts-row__icon">
					<Icon name={ icon.replace( 'ph-', '' ) } />
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
						<span className="ts-row__title">{ name }</span>
						<StatusPill tone={ tone } label={ status } />
					</div>
					<div className="ts-row__desc">
						{ stopped }{ ' ' }
						{ __(
							'attempts stopped in the last 7 days',
							'teksecurity'
						) }
					</div>
				</div>
				<Switch
					checked={ enabled }
					onChange={ onToggle }
					label={ name }
				/>
			</div>
		</section>
	);
}
