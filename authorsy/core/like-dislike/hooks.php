<?php
/**
 * Shortcode class
 *
 * @package Eas
 */

namespace Authorsy\Core\Like_Dislike;
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
        add_filter( 'the_content', [ $this, 'like_dislike_box' ] ); 
        add_shortcode('authorsy-like-dislike', [ $this, 'like_dislike_shortcode' ]);  
    }
 
    /**
     * Easy author box for frontend
     *
     * @param string $content The content of the post
     * @return string The modified content with the author box shortcode added
     */
    public function like_dislike_box( $content ) {  
        $settings = authorsy_get_settings(); 
        $post_type = get_post_type();  
        $visible_likes_box_on = !empty($settings['visible_likes_box_on']) ? $settings['visible_likes_box_on'] : [];  
        $likes_box_position = !empty($settings['likes_box_position']) ? $settings['likes_box_position'] : 'after_content';  
        $enable_like_dislikes = !empty($settings['enable_like_dislikes']) ? $settings['enable_like_dislikes'] : 'false';  
        $authorsy_like_box_disable = get_post_meta(get_the_ID(), 'authorsy_like_box_enable', true);
  
        if (in_array($post_type, $visible_likes_box_on)  && $enable_like_dislikes == "true") {
            $index = array_search($post_type, $visible_likes_box_on);
            $visible = $visible_likes_box_on[$index];
 
            if ($visible && $authorsy_like_box_disable !=='true' ) {
                $shortcode = do_shortcode( '[authorsy-like-dislike]' ); 
                if($likes_box_position == 'after_content'){
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
    public function like_dislike_shortcode($attr) {
        wp_enqueue_style('ea-frontend');
        wp_enqueue_style('ea-icon-fonts');
        wp_enqueue_script('ea-frontend-scripts'); 
        $settings           = authorsy_get_settings(); 
        $restriction        = !empty($settings['likes_dislike_restriction']) ? $settings['likes_dislike_restriction'] : 'no_restriction';
        $enable_social_share= !empty($settings['enable_social_share']) ? $settings['enable_social_share'] : false;
        $enable_feedback_form= !empty($settings['enable_feedback_form']) ? $settings['enable_feedback_form'] : false;
   
        
    
        $post_id            = isset( $attr['post_id'] ) ? $attr['post_id'] : get_the_ID();
        $permalink          = get_permalink($post_id);
        $thumbnail_url      = get_the_post_thumbnail_url($post_id, 'full');
        $title              = get_the_title($post_id);
        $data_controls = [
            'box_title' => __('Rate Your Vibes', 'authorsy'),
            'post_id' => $post_id,
            'restriction' => $restriction,
            'permalink' => $permalink,
            'thumbnail_url' => $thumbnail_url,
            'title' => $title,
            'site_email' => get_bloginfo('admin_email'),
            'enable_social_share' => $enable_social_share,
            'enable_feedback_form' => $enable_feedback_form
        ];
        $controls      = json_encode( $data_controls );

        ob_start();
        ?>
        <div class="authorsy-shortcode-wrapper">
            <div class="authorsy-like-dislike-box" data-controls="<?php echo esc_attr( $controls ); ?>"> 
            </div>
        </div>
        <?php
        return ob_get_clean();
    }
    
}


