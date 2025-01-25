<?php
/**
 * Admin menu class
 *
 * @package Authorsy
 */

namespace Authorsy\Core\Like_Dislike;

defined( 'ABSPATH' ) || exit;
use Error;

/**
 * Class Rating_Meta
 */
class Like_Dislike_Meta
{
    use \Authorsy\Utils\Singleton;

    /**
     * Initialize
     *
     * @return void
     */
    public function init()
    {
        add_action('add_meta_boxes', [$this, 'add_post_like_dislike_meta_box']);
        add_action('save_post', [$this, 'save_post_like_dislike_meta_box']);

        $settings = authorsy_get_settings(); 
        $visible_on  = !empty($settings['visible_likes_box_on']) ? $settings['visible_likes_box_on'] : [] ;
        $enable_like_dislikes  = !empty($settings['enable_like_dislikes']) ? $settings['enable_like_dislikes'] : 'false' ;
        
        if(!empty($visible_on &&  $enable_like_dislikes == "true")) {
            foreach ($visible_on as $post_type) {
                add_filter("manage_{$post_type}_posts_columns", [$this, 'like_dislike_meta_columns']);
                add_action("manage_{$post_type}_posts_custom_column", [$this, 'like_dislike_meta_column_data'], 10, 2);
            }
            
        }
       
    }

 

    public function add_post_like_dislike_meta_box() {
        $settings = authorsy_get_settings(); 
        $visible_on  = !empty($settings['visible_likes_box_on']) ? $settings['visible_likes_box_on'] : [] ;
        $enable_like_dislikes  = !empty($settings['enable_like_dislikes']) ? $settings['enable_like_dislikes'] : 'false' ;
        
        if(!empty($visible_on &&  $enable_like_dislikes == "true")) {
            add_meta_box(
                'authorsy-like-dislike',
                __('Authorsy Like & Dislike', 'authorsy'),
                [$this, 'render_post_like_dislike_meta_box'],
                $visible_on,  
                'side',
                'default'
            );
        }
      
    }

    public function render_post_like_dislike_meta_box($post) {

        // Create a nonce field
        wp_nonce_field('authorsy_meta_nonce', 'authorsy_meta_nonce');

        // Retrieve existing values for likes and dislikes
        $authorsy_like_box_enable = get_post_meta($post->ID, 'authorsy_like_box_enable', true);
 
    
        $likes = get_post_meta($post->ID, 'authorsy_likes', true);
        $likes = !empty( $likes ) ? $likes : 0;
        $dislikes = get_post_meta($post->ID, 'authorsy_dislikes', true); 
        $dislikes = !empty( $dislikes ) ? $dislikes : 0; 
        $loves = get_post_meta($post->ID, 'authorsy_loves', true);
        $loves = !empty( $loves ) ? $loves : 0;
        $angry = get_post_meta($post->ID, 'authorsy_angry', true); 
        $angry = !empty( $angry ) ? $angry : 0; 
        ?>
        <div class="authorsy-like-dislike">
            <div class="authorsy-likes-dislike-field" style="margin-bottom: 15px;">
                <label for="authorsy_like_box_enable" style="min-width: 100px; display: inline-block;"><?php esc_html_e('Disable like box ', 'authorsy'); ?></label>
                <input type="checkbox"  name="authorsy_like_box_enable" id="authorsy_like_box_enable" <?php checked($authorsy_like_box_enable, "true"); ?> />
            </div>
            <div class="authorsy-likes-dislike-field" style="margin-bottom: 15px;">
                <label for="authorsy_likes" style="min-width: 100px; display: inline-block;"><?php esc_html_e('Likes:', 'authorsy'); ?></label>
                <input type="number" name="authorsy_likes" id="authorsy_likes" value="<?php echo esc_attr($likes); ?>" />
            </div>
            <div class="authorsy-likes-dislike-field">
                <label for="authorsy_dislikes" style="min-width: 100px; display: inline-block;"><?php esc_html_e('Dislikes:', 'authorsy'); ?></label>
                <input type="number" name="authorsy_dislikes" id="authorsy_dislikes" value="<?php echo esc_attr($dislikes); ?>" />
            </div>
            <div class="authorsy-likes-dislike-field">
                <label for="authorsy_loves" style="min-width: 100px; display: inline-block;"><?php esc_html_e('Loves:', 'authorsy'); ?></label>
                <input type="number" name="authorsy_loves" id="authorsy_loves" value="<?php echo esc_attr($loves); ?>" />
            </div>
            <div class="authorsy-likes-dislike-field">
                <label for="authorsy_angry" style="min-width: 100px; display: inline-block;"><?php esc_html_e('Angrys:', 'authorsy'); ?></label>
                <input type="number" name="authorsy_angry" id="authorsy_angry" value="<?php echo esc_attr($angry); ?>" />
            </div>
        </div>
        <?php
    }

    public function save_post_like_dislike_meta_box($post_id) {
        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) return;
        if (!current_user_can('edit_post', $post_id)) return;

         // Verify nonce
         if (!isset($_POST['authorsy_meta_nonce']) || !wp_verify_nonce($_POST['authorsy_meta_nonce'], 'authorsy_meta_nonce')) {
            return;
        }

        // Sanitize and save likes and dislikes values 
        $enable_likebox = isset($_POST['authorsy_like_box_enable']) && $_POST['authorsy_like_box_enable'] === 'on' ? 'true' : 'false';
        update_post_meta($post_id, 'authorsy_like_box_enable', $enable_likebox);


        // Sanitize and save likes and dislikes values
        if (isset($_POST['authorsy_likes'])) {
            $likes = sanitize_text_field($_POST['authorsy_likes']);
            update_post_meta($post_id, 'authorsy_likes', $likes);
        }

        if (isset($_POST['authorsy_dislikes'])) {
            $dislikes = sanitize_text_field($_POST['authorsy_dislikes']);
            update_post_meta($post_id, 'authorsy_dislikes', $dislikes);
        }
        if (isset($_POST['authorsy_loves'])) {
            $loves = sanitize_text_field($_POST['authorsy_loves']);
            update_post_meta($post_id, 'authorsy_loves', $loves);
        }
        if (isset($_POST['authorsy_angry'])) {
            $angry = sanitize_text_field($_POST['authorsy_angry']);
            update_post_meta($post_id, 'authorsy_angry', $angry);
        }
    }

   public function like_dislike_meta_columns($columns) {
        $columns['votes'] = __('Likes & Dislikes', 'authorsy');
        return $columns;
    }
    
    // Display custom metadata in post columns
   public function like_dislike_meta_column_data($column, $post_id) {
        if ($column == 'votes') {
            $authorsy_likes = get_post_meta($post_id, 'authorsy_likes', true);
            $authorsy_dislikes = get_post_meta($post_id, 'authorsy_dislikes', true);
            $authorsy_loves = get_post_meta($post_id, 'authorsy_loves', true);
            $authorsy_angry = get_post_meta($post_id, 'authorsy_angry', true);
            $authorsy_likes = __("Likes: ", "authorsy") . $authorsy_likes;
            $authorsy_dislikes = __("Dislikes: ", "authorsy") . $authorsy_dislikes;
            $authorsy_loves = __("Loves: ", "authorsy") . $authorsy_loves;
            $authorsy_angry = __("Angers: ", "authorsy") . $authorsy_angry;
            echo esc_html($authorsy_likes) . "<br>" . esc_html($authorsy_dislikes) . "<br>" . esc_html($authorsy_loves) . "<br>" . esc_html($authorsy_angry);
        }
    }
}
