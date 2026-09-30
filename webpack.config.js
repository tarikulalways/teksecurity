/**
 * Two bundles: the admin app, and a small script for wp-login.php.
 */

const defaultConfig = require( '@wordpress/scripts/config/webpack.config' );

module.exports = {
	...defaultConfig,
	entry: {
		index: './src/index.js',
		login: './src/login.js',
	},
};
