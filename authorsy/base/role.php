<?php
/**
 * Register Custom Role
 *
 * @package Authorsy
 */
namespace Authorsy\Base;
defined( 'ABSPATH' ) || exit;
use Authorsy\Utils\Singleton;

/**
 * Class Role
 */
class Role {
    use Singleton;

    /**
     * Initialize
     *
     * @return void
     */
    public function init() {
        $this->register_role();
        $this->add_cap();
        $this->set_role();
    }

    /**
     * Register role for guest
     *
     * @return void
     */
    public function register_role() {
        $roles = $this->get_roles();

        foreach ( $roles as $role ) {
            add_role(
                $role['name'],
                $role['display_name'],
                $role['capabilities']
            );
        }
    }

    /**
     * Get roles
     *
     * @return  array
     */
    public function get_roles() {
        $roles = [
            [
                'name'         => 'authorsy-guest',
                'display_name' => esc_html__( 'Guest', 'authorsy' ),
                'capabilities' => [
                    'read' => true,
                ],
                 
            ], 
        ];

        return apply_filters( 'authorsy_guest_roles', $roles );
    }

    /**
     * Add capabilites to a role
     *
     * @return void
     */
    public function add_cap() {
        global $wp_roles; 
        $wp_roles->add_cap( 'administrator', 'manage_options' ); 
         
    }

    

    /**
     * Set user role
     *
     * @return  void
     */
    public function set_role() { 
        
		$users = get_users( ['role' => 'authorsy-guest'] ); 

        foreach ( $users as $user ) {
            if ( ! user_can( $user, 'delete_published_pages' ) ) {
                $user->add_cap( 'delete_published_pages', true );
            }
        }
    }
}
