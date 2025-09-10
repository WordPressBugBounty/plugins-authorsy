<?php
/**
 * Bootstrap Class
 *
 * @package Authorsy
 */
namespace Authorsy;

defined( 'ABSPATH' ) || exit;

/**
 * Bootstrap class.
 *
 * @since 1.0.0
 */
final class Bootstrap {

    /**
     * @var Bootstrap The Actual Authorsy instance
     * @since 1.0.0
     */
    private static $instance;

	/**
	 * @var string $file The plugin file path.
	 * @since 1.0.0
	 */
	private $file;
	
	/**
	 * @var string $version The plugin version.
	 * @since 1.0.0
	 */
	public $version;
    /**
     * Throw Error While Trying To Clone Object
     *
     * @since 1.0.0
     * @return void
     */
    public function __clone() {
        _doing_it_wrong( __FUNCTION__, esc_html__( 'Cloning is forbidden.', 'authorsy' ), '1.0.0' );
    }

    /**
     * Disabling Un-serialization Of This Class
     */
    public function __wakeup() {
        _doing_it_wrong( __FUNCTION__, esc_html__( 'Unserializing instances of this class is forbidden.', 'authorsy' ), '1.0.0' );
    }

    /**
     * The actual authorsy instance
     *
     * @since 1.0.0
     * @param string $file
     * @return void
     */
    public static function instantiate( $file = '' ) {

        // Return if already instantiated
        if ( self::instantiated() ) {
            return self::$instance;
        }

        self::prepare_instance( $file );

        self::$instance->initialize_constants();
        self::$instance->define_tables();
        self::$instance->include_files();
        self::$instance->initialize_components();

        return self::$instance;
    }

    /**
     * Return If The Main Class has Already Been Instantiated Or Not
     *
     * @since 1.0.0
     * @return boolean
     */
    private static function instantiated() {
        if ( ( null !== self::$instance ) && ( self::$instance instanceof Bootstrap ) ) {
            return true;
        }

        return false;
    }

    /**
     * Prepare Singleton Instance
     *
     * @since 1.0.0
     * @param string $file
     * @return void
     */
    private static function prepare_instance( $file = '' ) {
        self::$instance          = new self();
        self::$instance->file    = $file;
        self::$instance->version = \Authorsy::get_version();
    }

    /**
     * Assets Directory URL
     *
     * @since 1.0.0
     * @return void
     */
    public function get_assets_url() {
        return trailingslashit( $this->get_plugin_url() . 'assets' );
    }

    /**
     * Assets Directory Path
     *
     * @since 1.0.0
     * @return void
     */
    public function get_assets_dir() {
        return trailingslashit( $this->get_plugin_dir() . 'assets' );
    }

    /**
     * Plugin Directory URL
     *
     * @return void
     */
    public function get_plugin_url() {
        return trailingslashit( plugin_dir_url( $this->file ) );
    }

    /**
     * Plugin Directory Path
     *
     * @return void
     */
    public function get_plugin_dir() {
        return \Authorsy::get_plugin_dir();
    }

    /**
     * Plugin Basename
     *
     * @return void
     */
    public function get_plugin_basename() {
        return plugin_basename( $this->file );
    }

    /**
     * Setup Plugin Constants
     *
     * @since 1.0.0
     * @return void
     */
    private function initialize_constants() {
        // Plugin Version
        define( 'AUTHORSY_VERSION', \Authorsy::get_version() );

        // Plugin Main File
        define( 'AUTHORSY_PLUGIN_FILE', $this->file );

        // Plugin File Basename
        define( 'AUTHORSY_PLUGIN_BASE', $this->get_plugin_basename() );

        // Plugin Main Directory Path
        define( 'AUTHORSY_PLUGIN_DIR', $this->get_plugin_dir() );

        // Plugin Main Directory URL
        define( 'AUTHORSY_PLUGIN_URL', $this->get_plugin_url() );

        // Plugin Assets Directory URL
        define( 'AUTHORSY_ASSETS_URL', $this->get_assets_url() );

        // Plugin Assets Directory Path
        define( 'AUTHORSY_ASSETS_DIR', $this->get_assets_dir() );


    }

 

    /**
     * Define DB Tables Required For This Plugin
     *
     * @since 1.0.0
     * @return void
     */
    private function define_tables() {
        // To Be Implemented
    }

    /**
     * Include All Required Files
     *
     * @since 1.0.0
     * @return void
     */
    private function include_files() {
 
        /**
		 * Core helpers.
		 */
		require_once $this->get_plugin_dir() . 'utils/global-helper.php';
    }

    /**
     * Initialize All Components
     *
     * @since 1.0.0
     * @return void
     */
    private function initialize_components() {

        // Register scripts and styles first
        if ( $this->is_request( 'admin' ) ) {
            add_action( 'admin_enqueue_scripts', [ $this, 'admin_scripts' ] );
        }

        if ( $this->is_request( 'frontend' ) ) {
            add_action( 'wp_enqueue_scripts', array( $this, 'frontend_scripts' ) );
        }

        // Register admin menu
        Core\Admin\Menu::instance()->init();
        Core\Base::instance()->init();  
       
    }

    
    /**
     * Register scripts and styles for admin
     *
     * @return void
     */
    public function admin_scripts( ) {
    
        // get screen id.
		$screen    = get_current_screen();
		$screen_id = $screen->id;  
        $settings = authorsy_get_settings(); 
        $allowed_screen_ids = !empty($settings['visible_author_on']) ? $settings['visible_author_on'] : [] ;
        $enable_multi_author = !empty($settings['enable_multi_author']) ? $settings['enable_multi_author'] : "" ;
    
      
        if ( in_array( $screen_id, $allowed_screen_ids )  &&  $enable_multi_author) { 
            wp_enqueue_style( 'ea-select2', plugin_dir_url( __FILE__ ) . 'assets/css/select2.min.css', [], \Authorsy::get_version(), 'all' );
            wp_enqueue_script( 'ea-select2', plugin_dir_url( __FILE__ ) . 'assets/js/vendors/select2.min.js', [ 'jquery' ], \Authorsy::get_version(), true );
        }


        if (  'toplevel_page_authorsy' == $screen_id ) { 

            wp_enqueue_media();
            wp_enqueue_style( 'wp-color-picker' );
            wp_enqueue_style( 'authorsy-vendor',  plugin_dir_url( __FILE__ ). 'assets/css/vendor.css', [], \Authorsy::get_version(), 'all' );
            wp_enqueue_style( 'authorsy-admin-style',  plugin_dir_url( __FILE__ ) . 'assets/css/admin.css', [], \Authorsy::get_version(), 'all' );
            wp_enqueue_style( 'ea-icon-fonts',  plugin_dir_url( __FILE__ ) . 'assets/fonts/icon.css', [], \Authorsy::get_version(), 'all' );
            wp_enqueue_script( 'authorsy-antd-scripts',  plugin_dir_url( __FILE__ ) . 'assets/js/vendors/antd.js', [ 'wp-i18n','wp-element'], \Authorsy::get_version(), true );

            wp_enqueue_script( 'authorsy-dashboard-scripts',  plugin_dir_url( __FILE__ ) . 'assets/js/dashboard.js', ['authorsy-antd-scripts', 'wp-color-picker' ], \Authorsy::get_version(), true );
            $localize_obj = array(
                'site_url'            => site_url(),
                'admin_url'           => admin_url(),
                'nonce'               => wp_create_nonce( 'wp_rest' ),   
                'isPro'               => class_exists('AuthorsyPro') ? true : false
            );
            wp_localize_script( 'authorsy-dashboard-scripts', 'authorsy', $localize_obj );
            wp_set_script_translations( 'authorsy-dashboard-scripts', 'authorsy', \Authorsy::get_plugin_dir() . 'languages/' );

        }
    }

    /**
     * Register scripts and styles for frontend
     *
     * @return void
     */
    public function frontend_scripts() {
         wp_register_style( 'ea-icon-fonts',  plugin_dir_url( __FILE__ ) . 'assets/fonts/icon.css', [], \Authorsy::get_version(), 'all' );
         wp_register_style( 'ea-frontend',  plugin_dir_url( __FILE__ ) . 'assets/css/frontend.css', [], \Authorsy::get_version(), 'all' );
         wp_register_script( 'ea-frontend-scripts',  plugin_dir_url( __FILE__ ) . 'assets/js/frontend.js', [ 'jquery', 'wp-plugins' ], \Authorsy::get_version(), true );
         $localize_obj = array(
            'site_url'            => site_url(),
            'admin_url'           => admin_url(),
            'nonce'               => wp_create_nonce( 'wp_rest' ),   
            'isPro'               => class_exists('AuthorsyPro') ? true : false,
            'login'               => is_user_logged_in() ? true : false,
        );
        wp_localize_script( 'ea-frontend-scripts', 'authorsy', $localize_obj );
        wp_set_script_translations( 'ea-frontend-scripts', 'authorsy', \Authorsy::get_plugin_dir() . 'languages/' );

    }

    /**
     * What type of request
     *
     * @param string $type admin,frontend, ajax, cron
     * @return boolean
     */
    private function is_request( $type ) {
        switch ( $type ) {
            case 'admin':
                return is_admin();
            case 'ajax':
                return defined( 'DOING_AJAX' );
            case 'cron':
                return defined( 'DOING_CRON' );
            case 'frontend':
                return ( ! is_admin() || defined( 'DOING_AJAX' ) ) && ! defined( 'DOING_CRON' ) && ! $this->is_rest_api_request();
        }
    }

    /**
     * Returns if the request is non-legacy REST API request.
     *
     * @return boolean
     */
    private function is_rest_api_request() {
        $server_request = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : false;

        if ( ! $server_request ) {
            return false;
        }

        $rest_prefix        = trailingslashit( rest_get_url_prefix() );
        $is_rest_request    = ( false !== strpos( $server_request, $rest_prefix ) );

		return apply_filters( 'authorsy_is_rest_api_request', $is_rest_request );
    }

}

/**
 * Returns The Instance Of Authorsy.
 * The main function that is responsible for returning Authorsy instance.
 *
 * @since 1.0.0
 * @return Authorsy
 */
function authorsy() {
    return Bootstrap::instantiate();
}
