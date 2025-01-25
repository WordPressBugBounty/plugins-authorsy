<?php
/**
 * Shortcode class
 *
 * @package Eas
 */

namespace Authorsy\Core\Authors;
defined( 'ABSPATH' ) || exit;

use Authorsy\Utils\Singleton;
use Authorsy\Core\Authors\Author;
/**
 * Class Shortcode
 */
class Hooks {
    use Singleton;

    /**
     * Initialize the shortcode class
     *
     * @return  void
     */
    public function init() {  
        add_filter( 'the_content', [ $this, 'authorsy_box' ] ); 
        add_shortcode('authorsy-author-box', [ $this, 'authorsy_author_shortcode' ]); 
        add_filter( 'get_avatar', [$this, 'authorsy_set_avatar'], 10, 5 );
        add_action('init', [$this, 'set_guest_role_permissions']);

    }
 
   
    public function set_guest_role_permissions() {
        // Get the guest role
        $guest_role = get_role('authorsy-guest');
    
        if ($guest_role) {
            // Allow guest users to log in and view the admin panel
            $guest_role->add_cap('read'); // Allows access to the dashboard.
    
            // Permissions to view and edit posts and pages
            $guest_role->add_cap('edit_posts');   // Can edit their own posts.
            $guest_role->add_cap('edit_pages');  // Can edit their own pages.
    
            // Permissions to manage their own posts and pages
            $guest_role->add_cap('delete_posts'); // Can delete their own posts.
            $guest_role->add_cap('delete_pages'); // Can delete their own pages.
    
            // Viewing permissions
            $guest_role->add_cap('read_post'); // Allows reading specific posts.
            $guest_role->add_cap('read_page'); // Allows reading specific pages.
    
            // Restrict editing or deleting other users' content
            $guest_role->remove_cap('edit_others_posts'); // Cannot edit others' posts.
            $guest_role->remove_cap('edit_others_pages'); // Cannot edit others' pages.
            $guest_role->remove_cap('delete_others_posts'); // Cannot delete others' posts.
            $guest_role->remove_cap('delete_others_pages'); // Cannot delete others' pages.
    
            // Remove publish capabilities
            $guest_role->remove_cap('publish_posts'); // Cannot publish their own posts.
            $guest_role->remove_cap('publish_pages'); // Cannot publish their own pages.
    
            // Remove capabilities to edit or delete published posts and pages
            $guest_role->remove_cap('edit_published_posts'); // Cannot edit their published posts.
            $guest_role->remove_cap('edit_published_pages'); // Cannot edit their published pages.
            $guest_role->remove_cap('delete_published_posts'); // Cannot delete their published posts.
            $guest_role->remove_cap('delete_published_pages'); // Cannot delete their published pages.
        }
    }
     
    
 
    /**
     * Easy author box for frontend
     *
     * @param string $content The content of the post
     * @return string The modified content with the author box shortcode added
     */
    public function authorsy_box( $content ) {  
        $settings = authorsy_get_settings(); 
        $post_type = get_post_type();  
        $visible_author = !empty($settings['visible_author_on']) ? $settings['visible_author_on'] : [];  
        $author_position = !empty($settings['author_position']) ? $settings['author_position'] : 'after_content';  
        $enable_author_box = !empty($settings['enable_author_box']) ? $settings['enable_author_box'] : "false";  
  
        if (in_array($post_type, $visible_author) && is_single() && $enable_author_box == "true") {
            $index = array_search($post_type, $visible_author);
            $visible = $visible_author[$index];
 
            if ($visible) {
                $shortcode = do_shortcode( '[authorsy-author-box]' ); 
                if($author_position == 'after_content'){
                    $content .= $shortcode;
                }else {
                    $content = $shortcode . $content;
                }
                
            }
        }
        
    
        return $content; 
    }

    /**
     * Generates the HTML markup for displaying the author box.
     *
     * @return string The HTML markup for the author box.
     */
    public function authorsy_author_shortcode($attr) {
        wp_enqueue_style('ea-frontend');
        wp_enqueue_style('ea-icon-fonts');
        wp_enqueue_script('ea-frontend-scripts'); 
    
        $selected_author    = get_post_meta(get_the_ID(), 'ea_selected_author'); 
        $current_author_id  = !empty($attr['user_ids']) ? explode(',', $attr['user_ids']) : [get_the_author_meta('ID')];
        $selected_author    = !empty($selected_author) ? $selected_author : $current_author_id;
        $user_roles         = authorsy_get_author_roles();
        $settings           = authorsy_get_settings();
        $selected_layout    = !empty($settings['select_layout']) ? $settings['select_layout'] : 'style1';
        $layouts            = !empty($attr['layout']) ? $attr['layout'] : $selected_layout;

         $data_controls = [ 
            'layout'=> $layouts,
            'selected_author' => $selected_author, 
            'settings' => $settings,

        ];
        $controls      = json_encode( $data_controls );

        ob_start();
        ?>
        <div class="authorsy-shortcode-wrapper">
            <div class="authorsy-author-wrapper"
                 data-controls="<?php echo esc_attr( $controls ); ?>"></div>
        </div>
        <?php
        return ob_get_clean(); 
    }
 
    /**
     * Generates a function comment for the given function body.
     *
     * @param mixed $avatar The avatar to set.
     * @param mixed $id_or_email The ID or email of the user.
     * @param int $size The size of the avatar.
     * @param string $default The default avatar.
     * @param string $alt The alternative text for the avatar.
     * @return mixed The modified avatar.
     */
    public function authorsy_set_avatar( $avatar, $id_or_email, $size, $default, $alt ) {
    
        // If is email, try and find user ID
        if (!is_numeric($id_or_email)) {
            if (is_a($id_or_email, 'WP_Comment')) {
                // If the provided argument is a WP_Comment object, get the email from the comment
                $email = get_comment_author_email($id_or_email);
            } elseif (is_email($id_or_email)) {
                // If the provided argument is a string and a valid email, use it
                $email = $id_or_email;
            } else {
                // If not user ID and not a valid email, return
                return $avatar;
            }

            $user = get_user_by('email', $email);
            if ($user) {
                $id_or_email = $user->ID;
            }
        }
    
        // If not user ID, return
        if ( ! is_numeric( $id_or_email ) ) {
            return $avatar;
        }
        $author_info = new Author($id_or_email); 

        
 
        // Find URL of saved avatar in user meta
        $saved = $author_info->get_image(); 
        $get_image_id = $author_info->get_image_id();   
        $display_name = $author_info->get_full_name(); 
        if ( empty( $saved ) ) {
            return $avatar;
        }
        
        // Check if it is a URL
        if ( filter_var( $saved, FILTER_VALIDATE_URL ) ) {
            // Return saved image
            return wp_get_attachment_image( $get_image_id, [ $size, $size ], false, ['alt' => $display_name, 'class' => 'avatar'] );

         } 
        // Return normal
        return $avatar;
    }
        
    
}


