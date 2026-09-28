/**
 * Icons, drawn from the sprite the plugin ships.
 *
 * The sprite is inlined into the page by PHP, so the admin makes no outside
 * request for its iconography and works with no network at all.
 */

/**
 * One icon.
 *
 * @param {Object} props        Component props.
 * @param {string} props.name   Icon name without the `ph-` prefix, e.g. "shield-check".
 * @param {string} props.weight regular|fill|bold.
 * @param {number} props.size   Pixel size.
 * @param {string} props.className Extra classes.
 * @return {JSX.Element} The icon.
 */
export default function Icon( {
	name,
	weight = 'regular',
	size = 16,
	className = '',
} ) {
	const id = weight === 'regular' ? `ph-${ name }` : `ph-${ weight }-${ name }`;

	return (
		<svg
			className={ `ts-icon ${ className }`.trim() }
			width={ size }
			height={ size }
			fill="currentColor"
			aria-hidden="true"
			focusable="false"
		>
			<use href={ `#${ id }` } />
		</svg>
	);
}
