/**
 * Small presentational pieces shared by every screen.
 */

import { __, _n, sprintf } from '@wordpress/i18n';
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
										{ __( 'Recommended', 'teksecurity' ) }
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
 * A labelled field wrapper.
 *
 * Label, control and hint always sit in the same order with the same spacing,
 * and an error turns the border and the hint red together rather than one
 * screen doing it one way and the next doing it another.
 *
 * @param {Object}      props          Component props.
 * @param {string}      props.label    Field label.
 * @param {string}      props.hint     Helper text under the control.
 * @param {string}      props.error    Error message; replaces the hint when set.
 * @param {boolean}     props.narrow   Cap the width for a lone field in a card.
 * @param {JSX.Element} props.children The control.
 * @return {JSX.Element} The field.
 */
export function Field( { label, hint, error, narrow = false, children } ) {
	const text = error || hint;

	return (
		<label className={ `ts-field${ narrow ? ' ts-field--narrow' : '' }` }>
			{ label }
			{ children }
			{ text && (
				<span
					className={ `ts-hint${ error ? ' ts-hint--error' : '' }` }
				>
					{ text }
				</span>
			) }
		</label>
	);
}

/**
 * A labelled select.
 *
 * @param {Object}   props          Component props.
 * @param {string}   props.label    Field label.
 * @param {string}   props.value    Selected value.
 * @param {Array}    props.options  [ value, label ] pairs.
 * @param {Function} props.onChange Called with the next value.
 * @param {boolean}  props.disabled Whether the control is locked.
 * @param {string}   props.hint     Helper text.
 * @return {JSX.Element} The field.
 */
export function SelectField( {
	label,
	value,
	options,
	onChange,
	disabled = false,
	hint,
} ) {
	return (
		<Field label={ label } hint={ hint }>
			<select
				className="ts-select"
				value={ value }
				disabled={ disabled }
				onChange={ ( event ) => onChange( event.target.value ) }
			>
				{ options.map( ( [ key, text ] ) => (
					<option key={ key } value={ key }>
						{ text }
					</option>
				) ) }
			</select>
		</Field>
	);
}

/**
 * A labelled text input.
 *
 * @param {Object}   props             Component props.
 * @param {string}   props.label       Field label.
 * @param {string}   props.value       Current value.
 * @param {Function} props.onChange    Called with the next value.
 * @param {string}   props.type        Input type.
 * @param {string}   props.placeholder Placeholder.
 * @param {string}   props.hint        Helper text.
 * @param {string}   props.error       Error message.
 * @param {boolean}  props.narrow      Cap the width.
 * @param {Function} props.onEnter     Called when Enter is pressed.
 * @param {Object}   props.inputProps  Extra props for the input element.
 * @return {JSX.Element} The field.
 */
export function TextField( {
	label,
	value,
	onChange,
	type = 'text',
	placeholder,
	hint,
	error,
	narrow = false,
	onEnter,
	inputProps = {},
} ) {
	return (
		<Field label={ label } hint={ hint } error={ error } narrow={ narrow }>
			<input
				type={ type }
				className={ `ts-input${ error ? ' ts-input--error' : '' }` }
				value={ value }
				placeholder={ placeholder }
				onChange={ ( event ) => onChange( event.target.value ) }
				onKeyDown={ ( event ) => {
					if ( onEnter && event.key === 'Enter' ) {
						onEnter();
					}
				} }
				{ ...inputProps }
			/>
		</Field>
	);
}

/**
 * A row title with badges beside it.
 *
 * @param {Object}      props          Component props.
 * @param {string}      props.title    The name.
 * @param {JSX.Element} props.children Badges and pills.
 * @return {JSX.Element} The title row.
 */
export function TitleRow( { title, children } ) {
	return (
		<div className="ts-titlerow">
			<span className="ts-row__title">{ title }</span>
			{ children }
		</div>
	);
}

/**
 * The name of an attack type.
 *
 * One appearance everywhere it is shown, so the same attack does not read as
 * two different things between the dashboard, the log and the drawer.
 *
 * @param {Object} props       Component props.
 * @param {string} props.type  Attack type key.
 * @param {string} props.label Pre-resolved label, when the API already sent one.
 * @return {JSX.Element} The tag.
 */
export function AttackTag( { type, label } ) {
	const types =
		( window.tekSecurityData && window.tekSecurityData.types ) || {};
	const text = label || ( types[ type ] && types[ type ].label ) || type;

	return <span className="ts-tag ts-tag--attack">{ text }</span>;
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
 * The header card at the top of every single-module screen.
 *
 * It owns the whole "is this protection on" idea: the status wording, the
 * tone, the dimming when it is off and the switch. Screens pass what the
 * module is and whether it is enabled, never how to colour it.
 *
 * @param {Object}   props          Component props.
 * @param {string}   props.icon     Icon name, without the `ph-` prefix.
 * @param {string}   props.name     Module name.
 * @param {boolean}  props.enabled  Whether the module is on.
 * @param {Function} props.onToggle Called with the next state.
 * @param {number}   props.stopped  Attempts stopped in the last 7 days.
 * @param {string}   props.desc     Description, when "N attempts stopped" does not fit.
 * @param {string}   props.status   Status label, when it is not simply Active/Off.
 * @param {string}   props.tone     Status tone, when it is not simply ok/bad.
 * @param {string}   props.toggleLabel Accessible label for the switch.
 * @return {JSX.Element} The header card.
 */
export function ModuleHeader( {
	icon,
	name,
	enabled,
	onToggle,
	stopped,
	desc,
	status,
	tone,
	toggleLabel,
} ) {
	const label =
		status ||
		( enabled
			? __( 'Active', 'teksecurity' )
			: __( 'Off', 'teksecurity' ) );

	const description =
		desc ??
		sprintf(
			/* translators: %d: number of attempts stopped in the last 7 days. */
			_n(
				'%d attempt stopped in the last 7 days',
				'%d attempts stopped in the last 7 days',
				stopped || 0,
				'teksecurity'
			),
			stopped || 0
		);

	return (
		<section className="ts-card">
			<div className={ `ts-row${ enabled ? '' : ' ts-row--dim' }` }>
				<div className="ts-row__icon">
					<Icon name={ icon } size={ 17 } />
				</div>
				<div className="ts-row__grow">
					<TitleRow title={ name }>
						<StatusPill
							tone={ tone || ( enabled ? 'ok' : 'bad' ) }
							label={ label }
						/>
					</TitleRow>
					<div className="ts-row__desc">{ description }</div>
				</div>
				<Switch
					checked={ enabled }
					onChange={ onToggle }
					label={ toggleLabel || name }
				/>
			</div>
		</section>
	);
}
