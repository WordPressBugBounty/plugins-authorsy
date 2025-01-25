<?php
/**
 * Admin hooks
 *
 * @package Authorsy
 */
namespace Authorsy\Core\Admin;
defined( 'ABSPATH' ) || exit;

use Authorsy\Utils\Singleton;
 

class Hooks {
    use Singleton;

    /**
     * Initialize admin hooks
     *
     * @return void
     */
    public function init() {
      
        add_filter('plugin_action_links', [ $this, 'add_settings_plugin_tab' ], 10, 2); 
  
    }
 
    /**
     * Add settings on plugin action row
     *
     * @param   array  $actions
     * @param   string  $plugin_file
     *
     * @return  array
     */
    public function add_settings_plugin_tab( $actions, $plugin_file ) {
        // Check if the plugin file matches your target plugin
        if ( 'authorsy/authorsy.php' === $plugin_file ) {
            // Add your custom tab
            $settings_tab = array(
                'authorsy-settings' => sprintf( '<a href="%s">%s</a>', esc_url( admin_url('admin.php?page=authorsy#/settings') ), __( 'Settings', 'authorsy' ) ),
            );
            // Merge the custom tab with existing actions
            $actions = array_merge( $settings_tab, $actions );
        }
        return $actions;
    }

   
 
}
