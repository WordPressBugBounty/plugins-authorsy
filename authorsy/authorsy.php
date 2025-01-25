<?php

/**
 * Plugin Name:       Authorsy
 * Plugin URI:        https://themeplugs.com/
 * Description:       Author box and bio link for WordPress.
 * Version:           1.0.4
 * Requires at least: 5.2
 * Requires PHP:      7.3
 * Author:            themeplugs
 * Author URI:        https://themeplugs.com/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       authorsy
 * Domain Path:       /languages

 * Authorsy is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * any later version.

 * You should have received a copy of the GNU General Public License
 * along with Authorsy. If not, see <http://www.gnu.org/licenses/>.
 *
 * @package Authorsy
 * @category Core
 * @author themeplugs
 * @version 1.0.0
 */

use Authorsy as GlobalEasyAuthor;

// Exit if accessed directly.
defined( 'ABSPATH' ) || exit;

/**
 * The Main Plugin Requirements Checker
 *
 * @since 1.0.0
 */
final class Authorsy {

    /**
     * Static Property To Hold Singleton Instance
     *
     * @var Authorsy The Authorsy Requirement Checker Instance
     */
    private static $instance;

    /**
     * Plugin Current Production Version
     *
     * @return string
     */
    public static function get_version() {
        return '1.0.4';
    }

    /**
     * Requirements Array
     *
     * @since 1.0.0
     * @var array
     */
    private $requirements = array(
        'php' => array(
            'name'    => 'PHP',
            'minimum' => '7.3',
            'exists'  => true,
            'met'     => false,
            'checked' => false,
            'current' => false,
        ),
        'wp'  => array(
            'name'    => 'WordPress',
            'minimum' => '5.2',
            'exists'  => true,
            'checked' => false,
            'met'     => false,
            'current' => false,
        ),
    );

    /**
     * Singleton Instance
     *
     * @return Authorsy
     */
    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Setup Plugin Requirements
     *
     * @since 1.0.0
     */
    private function __construct() {
        // Always load translation.
        add_action( 'plugins_loaded', array( $this, 'load_text_domain' ) );

        // Initialize plugin functionalities or quit.
        $this->requirements_met() ? $this->initialize_modules() : $this->quit();
    }

    /**
     * Load Localization Files
     *
     * @since 1.0
     * @return void
     */
    public function load_text_domain() {
        $locale = apply_filters( 'plugin_locale', get_user_locale(), 'authorsy' );

        unload_textdomain( 'authorsy' );
        load_textdomain( 'authorsy', WP_LANG_DIR . '/authorsy/authorsy-' . $locale . '.mo' );
        load_plugin_textdomain( 'authorsy', false, self::get_plugin_dir() . 'languages/' );
    }

    /**
     * Initialize Plugin Modules
     *
     * @since 1.0.0
     * @return void
     */
    private function initialize_modules() {
        require_once dirname( __FILE__ ) . '/autoloader.php';
        require_once dirname( __FILE__ ) . '/core/settings/settings.php';

        require_once dirname( __FILE__ ) . '/utils/global-helper.php';

        // Include the bootstrap file if not loaded.
        if ( ! class_exists( 'Authorsy\Bootstrap' ) ) {
            require_once self::get_plugin_dir() . 'bootstrap.php';
        }

        // Initialize the bootstraper if exists.
        if ( class_exists( 'Authorsy\Bootstrap' ) ) {

            // Initialize all modules through plugins_loaded.
            add_action( 'plugins_loaded', array( $this, 'init' ) );

            register_activation_hook( self::get_plugin_file(), array( $this, 'activate' ) );
            register_deactivation_hook( self::get_plugin_file(), array( $this, 'deactivate' ) );
         }
    }

    /**
     * Check If All Requirements Are Fulfilled
     *
     * @return boolean
     */
    private function requirements_met() {
        $this->prepare_requirement_versions();

        $passed  = true;
        $to_meet = wp_list_pluck( $this->requirements, 'met' );

        foreach ( $to_meet as $met ) {
            if ( empty( $met ) ) {
                $passed = false;
                continue;
            }
        }

        return $passed;
    }

    /**
     * Requirement Version Prepare
     *
     * @since 1.0.0
     *
     * @return void
     */
    private function prepare_requirement_versions() {
        foreach ( $this->requirements as $dependency => $config ) {
            switch ( $dependency ) {
            case 'php':
                $version = phpversion();
                break;
            case 'wp':
                $version = get_bloginfo( 'version' );
                break;
            default:
                $version = false;
            }

            if ( ! empty( $version ) ) {
                $this->requirements[$dependency]['current'] = $version;
                $this->requirements[$dependency]['checked'] = true;
                $this->requirements[$dependency]['met']     = version_compare( $version, $config['minimum'], '>=' );
            }
        }
    }

    /**
     * Initialize everything
     *
     * @since 1.0.0
     *
     * @return void
     */
    public function init() {
        Authorsy\Bootstrap::instantiate( self::get_plugin_file() );
    }

    /**
     * Called Only Once While Activation
     *
     * @return void
     */
    public function activate() { 
        // Insert new role.
         Authorsy\Base\Role::instance()->init();
        // Update default settings.
        authorsy_update_default_settings();
  
    }
    /**
     * Called Only Once While Activation
     *
     * @return void
     */
    public function deactivate() {  
  
    }

    /**
     * Quit Plugin Execution
     *
     * @return void
     */
    private function quit() {
        add_action( 'admin_head', array( $this, 'show_plugin_requirements_not_met_notice' ) );
    }

    /**
     * Show Error Notice For Missing Requirements
     *
     * @return void
     */
    public function show_plugin_requirements_not_met_notice() {
        printf( '<div>Minimum requirements for Authorsy are not met. Please update requirements to continue.</div>' );
    }

    /**
     * Plugin Main File
     *
     * @return string
     */
    public static function get_plugin_file() {
        return __FILE__;
    }

    /**
     * Plugin Base Directory Path
     *
     * @return string
     */
    public static function get_plugin_dir() {
        return trailingslashit( plugin_dir_path( self::get_plugin_file() ) );
    }
}

Authorsy::get_instance();


