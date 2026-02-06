<?php
/**
 * Author Class
 *
 * @package Authorsy
 */
namespace Authorsy\Core\Authors;
defined( 'ABSPATH' ) || exit;
use Error;
use WP_User_Query;

/**
 * Class Author
 */
class Author {
    /**
     * Store Author role
     *
     * @var string
     */
    protected $role = 'authorsy-guest';

    /**
     * Store meta prefix
     *
     * @var string
     */
    protected $meta_prefix = '_ea_';

    /**
     * Store Author id
     *
     * @var integer
     */
    protected $id;

    /**
     * Store Author data
     *
     * @var array
     */
    protected $data = [
        'first_name' => '',
        'last_name'  => '',
        'user_email' => '',
        'image'      => '',
        'image_id'      => '',
        'user_login' => '',
        'phone'      => '', 
        'role'       => '',
        'social'     => [],
        'extra_bio'  => [],
        'description' => '',
        'designation'     => '',  
    ];

    /**
     * Store WP_Error
     *
     * @var Object
     */
    public $error;

    /**
     * Author Constructor
     *
     * @return void
     */
    public function __construct( $author = 0 ) {
        if ( $author instanceof self ) {
            $this->set_id( $author->get_id() );
        } elseif ( ! empty( $author->ID ) ) {
            $this->set_id( $author->ID );
        } elseif ( is_numeric( $author ) && $author > 0 ) {
            $this->set_id( $author );
        }
    }

    /**
     * Get user id
     *
     * @return  integer
     */
    public function get_id() {
        return $this->id;
    }

    /**
     * Get first name
     *
     * @return string
     */
    public function get_first_name() {
        return $this->get_prop( 'first_name', $this->get_display_name() ); 
    }

    /**
     * Get last name
     *
     * @return  string
     */
    public function get_last_name() {
        return $this->get_prop( 'last_name', $this->get_display_name() );
        
    } 
    /**
     * Get author display name
     *
     * @return  string
     */
    public function get_display_name() {
        $user         = get_userdata( $this->id );
        $display_name = '';

        if ( $user ) {
            $display_name = $user->display_name;
        }

        return $display_name;
    }
    /**
     * Get author display name
     *
     * @return  string
     */
    public function get_full_name() {
        $user         = get_userdata( $this->id );
        $full_name = $this->get_display_name();

        if ( $user ) {
            $full_name = $user->first_name." ". $user->last_name;
        }

        return $full_name;
    }

    /**
     * Get user email
     *
     * @return  string
     */
    public function get_email() {
        return get_userdata( $this->id )->user_email;
    }

    /**
     * Get phone
     *
     * @return string
     */
    public function get_phone() {
        return $this->get_prop( 'phone', '' );
    }
    /**
     * Get socials
     *
     * @return string
     */
    public function get_social() {
        return $this->get_prop( 'social', [] );
    }
    /**
     * Get socials
     *
     * @return string
     */
    public function get_extra_bio() {
        return $this->get_prop( 'extra_bio', [] );
    }

    /**
     * Get image
     *
     * @return  string
     */
    public function get_image() {
        $image = $this->get_prop( 'image' ); 
        if ( filter_var( $image, FILTER_VALIDATE_URL ) ) {
            return $image;
        } 
        if ( ! $image ) {
            return false;
        }

        return wp_get_attachment_image_url( $image );
    }
    /**
     * Get image
     *
     * @return  string
     */
    public function get_image_id() {
        $image = $this->get_prop( 'image_id', '' );  
        return $image;
    }

    /**
     * Get user name
     *
     * @return  string
     */
    public function get_user_name() { 
        return get_userdata($this->id)->user_login;
    }
  
   
    public function get_user_role() {
        $user_data = get_userdata($this->id);
        $roles = $user_data->roles;
        
        if (!empty($roles)) {
            return $roles[0]; // Return the first role as a string
        } else {
            return ''; // Return an empty string if no role is found
        }
    } 

    /**
     * Retrieves the designation of the user associated with this object.
     *
     * @return string The designation  of the user. Returns an empty string if the user is not found or doesn't have a designation.
     */
    public function get_designation() {
        return $this->get_prop( 'designation', '' );
    }
    
   /**
     * Get description
     *
     * @return  string
     */
    public function get_description() { 
        return get_userdata($this->id)->description; 
    }

   /**
     * Get permalink
     *
     * @return  string
     */
    public function get_permalink() { 
        return get_author_posts_url($this->id); 
    }
  
    /**
     * Get all data for a author
     *
     * @return array
     */
    public function get_data() { 
        $is_authenticated = is_user_logged_in();
        
        $data = [
            'id'         => $this->get_id(),
            'full_name'  => $this->get_full_name(),
            'first_name' => $this->get_first_name(),
            'last_name'  => $this->get_last_name(),
            'image'      => $this->get_image(), 
            'social'     => $this->get_social(),
            'extra_bio'  => $this->get_extra_bio(),
            'description'=> $this->get_description(),
            'designation'=> $this->get_designation(),
            'image_id'   => $this->get_image_id(),
            'permalink'  => $this->get_permalink()
        ];
        
        // Only include sensitive fields for authenticated users
        if ( $is_authenticated ) {
            $data['user_name']  = $this->get_user_name();
            $data['user_email'] = $this->get_email();
            $data['phone']      = $this->get_phone();
            $data['role']       = $this->get_user_role();
        }
        
        return $data;
    }
    /**
     * Get all data for a author (frontend/public version)
     *
     * @return array
     */
    public function get_frontend_data() { 
        $is_authenticated = is_user_logged_in();
        
        $data = [
            'full_name'  => $this->get_full_name(),
            'first_name' => $this->get_first_name(),
            'last_name'  => $this->get_last_name(),  
            'image'      => $this->get_image(), 
            'social'     => $this->get_social(),
            'extra_bio'  => $this->get_extra_bio(),
            'description'=> $this->get_description(),
            'designation'=> $this->get_designation(),
            'image_id'   => $this->get_image_id(),
            'permalink'  => $this->get_permalink()
        ];
        
        // Only include phone and role for authenticated users
        if ( $is_authenticated ) {
            $data['phone'] = $this->get_phone();
            $data['role']  = $this->get_user_role();
        }
        
        return $data;
    }

    /**
     * Get  data
     *
     * @param   string  $prop
     *
     * @return  mixed
     */
    private function get_prop( $prop = '', $default = false ) {
        $data = $this->get_metadata( $prop );

        if ( ! $data ) {
            return $default;
        }

        return $data;
    }

    /**
     * Get metadata
     *
     * @param   string  $prop
     *
     * @return  mixed
     */
    private function get_metadata( $prop = '' ) {
        $meta_key = $this->meta_prefix . $prop;

        return get_user_meta( $this->id, $meta_key, true );
    }

    /**
     * Set id
     *
     * @param   integer  $id  User ID
     *
     * @return void
     */
    public function set_id( $id ) {
        $this->id = $id;
    }

    /**
     * Set props
     *
     * @param   array  $args  User Data
     *
     * @return  void
     */
    public function set_props( $args = [] ) {
        $this->data = wp_parse_args( $args, $this->data );
    }

    /**
     * Create author
     *
     * @param   array $args author data
     *
     * @return bool
     */
    public function create( $args = [] ) {
        $defaults = [
            'first_name' => '',
            'last_name'  => '',
            'user_login' => '',
            'user_email' => '',
            'user_pass'  => wp_generate_password(),
            'role'       => '', 
        ];

        $args    = wp_parse_args( $args, $defaults );
        $user_id = wp_insert_user( $args );

        if ( ! is_wp_error( $user_id ) ) {
            $this->set_id( $user_id );
            $this->save_metadata( $args );
            $this->retrieve_password();
        }

        return $user_id;
    }

    /**
     * Update author data
     *
     * @return  void
     */
    public function update($args = []) {
            $user = get_userdata($this->id)->to_array();

            if (!empty($args['user_pass'])) {
                $user['user_pass'] = $args['user_pass'];
            }

            if (!empty($args['user_email'])) {
                $user['user_email'] = $args['user_email'];
            }

            if (!empty($args['first_name'])) {
                $user['first_name'] = $args['first_name'];
            }

            if (!empty($args['last_name'])) {
                $user['last_name'] = $args['last_name'];
            } 
            if (!empty($args['description'])) {
                $user['description'] = $args['description'];
            }  
            if (!empty($args['role'])) { 
                $new_role = sanitize_key($args['role']);
                $user['role'] = $new_role;
            } 

            $updated = wp_update_user($user); 

            if (!is_wp_error($updated)) {
                $this->save_metadata($args);
            }

            return $updated;
        }

    /**
     * Update meta data
     *
     * @return  void
     */
    public function save_metadata( $data = []) {
        foreach ( $data as $key => $value ) {
            if ( ! isset( $this->data[ $key ] )) {
                continue;
            }

            // Prepare meta key.
            $meta_key = $this->meta_prefix . $key;

            // Update  meta data.
            update_user_meta( $this->id, $meta_key, $value );
        }
    }

    /**
     * Send password reset email
     *
     * @return void
     */
    public function retrieve_password() { 
        retrieve_password( $this->get_email() );
        
    }

    /**
     * Delete author
     *
     * @return  bool
     */
    public function delete() {
        require_once ABSPATH . 'wp-admin/includes/user.php';
        $user = get_userdata( $this->id ); 

        return wp_delete_user( $this->id );
    }

    /**
     * Check user is valid author
     *
     * @return  bool
     */ 
    public function is_author() {
        $user = get_userdata($this->id);

    
        if ($user) {
            $roles_to_check = authorsy_get_author_roles();  
            $user_roles = $user->roles;
    
            foreach ($roles_to_check as $role) {
                if (in_array($role, $user_roles, true)) {
                    return true;  
                }
            }
        }
    
        return false; 
    }

    /**
     * Get all  
     *
     * @param   array  $args   
     *
     * @return  array
     */
    public static function all( $args = [] ) {
        $defaults = [
            'role__in'   => authorsy_get_author_roles(),
            'number' => 20,
            'paged'  => 1,
        ];

        $args = wp_parse_args( $args, $defaults );

        $users = new WP_User_Query( $args );

        return [
            'total' => $users->get_total(),
            'items' => $users->get_results(),
        ];
    }
}
