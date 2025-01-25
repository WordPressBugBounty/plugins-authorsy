<?php

/**
 * Admin menu class
 *
 * @package Authorsy
 */

namespace Authorsy\Core\Authors;
defined( 'ABSPATH' ) || exit;
/**
 * Class Author_Meta
 */
class Author_Meta
{
    use \Authorsy\Utils\Singleton;

    /**
     * Initialize
     *
     * @return void
     */
    public function init()
    {
        $settings = authorsy_get_settings(); 
        add_filter('admin_body_class', array($this, 'enable_author_metabox_classes'));
        if (is_admin() && $settings['enable_multi_author'] == true) {
            add_action('add_meta_boxes', array($this, 'authorsy_author_meta_box'));
            add_action('save_post', array($this, 'save_authorsy_author_meta_box')); 
             
        }  
        add_filter('posts_where', array($this, 'authorsy_posts_where_filter'), 10, 2);
        add_filter('posts_join', array($this, 'authorsy_posts_join_filter'), 10, 2);
        add_filter('posts_distinct', array($this, 'authorsy_search_distinct'), 10);
     }
  

    /**
     * Generate the function comment for the given function body.
     *
     * @return void
     */
    public function authorsy_author_meta_box()
    {
        $settings = authorsy_get_settings(); 
        $visible_on  = !empty($settings['visible_author_on']) ? $settings['visible_author_on'] : [] ;
        if(!empty($visible_on)) {
            add_meta_box(
                'ea-author-box',
                __('Select Muliple Authors', 'authorsy'),
                array($this, 'render_authorsy_author_meta_box'), // Use an array to specify the callback
                $visible_on,
                'side',
                'default'
            );
        }
    }
    
    public function render_authorsy_author_meta_box($post)
    {
      
        // Get the selected authors for the current post as an array
        $coauthors = get_post_meta($post->ID, 'ea_selected_author'); 
 
        
        // Define the allowed roles
        $allowed_roles = authorsy_get_author_roles();
        
        // Get users based on allowed roles
        $all_users = get_users(array('role__in' => $allowed_roles));

        // Merge the selected authors with the allowed users
        $coauthors = array_merge(array($post->post_author), $coauthors);
        $coauthors  = array_unique($coauthors);
        $coauthors = array_values($coauthors);
        ?>
        <div class="ea-author-repeater">
        <p><?php echo esc_html__('Select Authors:', 'authorsy')?></p>
        
        <input type="hidden" name="ea_author_nonce" value="<?php echo esc_attr(wp_create_nonce('ea-author-nonce')); ?>" />
        <select name="ea_selected_author[]" multiple="multiple" class="ea-author-select">
            <?php
            // Add a default option (Super Admin) when $coauthors is null or empty
            if (empty($coauthors)) {
                ?>
                <option value="<?php echo esc_attr(get_current_user_id()); ?>" selected="selected">
                    <?php echo esc_html(wp_get_current_user()->display_name); ?>
                </option>

                <?php 
            }
            // Output the options
            if(!empty($all_users)){
                foreach ($all_users as $user) {
                    $selected = in_array($user->ID, (array) $coauthors) ? 'selected="selected"' : '';
                    ?>
                    <option value="<?php echo esc_attr($user->ID); ?>" <?php echo esc_attr($selected); ?>>
                        <?php echo esc_html($user->display_name); ?>
                    </option>
                    <?php
                }
            }
            ?>
        </select>
    </div> 
       
        <script>
           jQuery(document).ready(function ($) {
                // Initialize Select2
                $(".ea-author-select").select2({
                    sorter: function (data) {
                        return data.sort(function (a, b) {
                            return a.text.localeCompare(b.text);
                        });
                    }
                });

                // Get the default values from the server-side (PHP)
                var defaultValues = <?php echo json_encode($coauthors); ?>;

                // Set the default values in the Select2 box
                for (var i = 0; i < defaultValues.length; i++) {
                    var option = $(".ea-author-select option[value='" + defaultValues[i] + "']");
                    option.detach().appendTo($(".ea-author-select"));
                }

                // Attach select event listener
                $(".ea-author-select").on("select2:select", function (e) {
                    var selectedOption = $(e.params.data.element);
                    selectedOption.detach().appendTo($(this));
                    $(this).trigger("change.select2");
                });
            });
        </script>
        <style>
            .ea-enable-multi-author .edit-post-post-author {
                display: none;
            }
        </style>
        <?php
    }
     
    /**
     * Saves the selected author meta box for a post.
     *
     * @param int $post_id The ID of the post being saved.
     */
    public function save_authorsy_author_meta_box($post_id)
    {
        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) return;
        if (!current_user_can('edit_post', $post_id)) return;
        if (!isset($_POST['ea_author_nonce']) || !wp_verify_nonce($_POST['ea_author_nonce'], 'ea-author-nonce')) return;

        if (isset($_POST['ea_selected_author'])) {
            $post_arr = filter_input_array( INPUT_POST, FILTER_SANITIZE_SPECIAL_CHARS );
            $ea_selected_authors =  $post_arr['ea_selected_author']; 
            delete_post_meta($post_id, 'ea_selected_author');
    
            if (!empty($ea_selected_authors)) {
                // Save the selected authors
                foreach ($ea_selected_authors as $key => $value) {
                    add_post_meta($post_id, 'ea_selected_author', $value);
                }
    
                // Update the post author if authors are selected 
                $current_post = get_post($post_id);
                if ($current_post->post_author != $ea_selected_authors[0]) {
                    wp_update_post(array(
                        'ID' => $post_id,
                        'post_author' => $ea_selected_authors[0],
                    ));
                }
            }
        }
    } 

    /**
     * A filter to modify the join clause of the WordPress query for posts.
     *
     * @param string $join The current join clause.
     * @param WP_Query $query The WP_Query object.
     * @return string The modified join clause.
     */
    public function authorsy_posts_join_filter($join, $query)
    {
        global $wpdb; 
        $join .= " LEFT JOIN {$wpdb->postmeta} AS meta1 ON {$wpdb->posts}.ID = meta1.post_id ";
        return $join;
    }

    /**
     * Generates a function comment for the given function body.
     *
     * @param mixed $where The initial value of the $where parameter.
     * @param mixed $query The initial value of the $query parameter.
     * @throws Some_Exception_Class description of exception
     * @return mixed The modified value of the $where parameter.
     */
    public function authorsy_posts_where_filter($where, $query)
    {
        global $wpdb;
    
        if (is_author() && $query->is_main_query() && !is_admin()) {
    
            $author = array();
            $query_author_name_id = $query->get('author');
            
            if ($query_author_name_id) {
                $author = get_user_by('id', $query_author_name_id);
            }
    
            $where = preg_replace('/AND\s*\((?:' . $wpdb->posts . '\.)?post_author\s*=\s*\d+\)/', ' ', $where, 1); // Remove post_author for SQL query
            $where = preg_replace('/AND\s*' . $wpdb->posts . '\.post_author\s*IN\s*\([0-9]*\)/', ' ', $where, 1);
    
            $author_id = (int)$author->ID;
    
            // Use the alias 'meta1' instead of '$wpdb->postmeta'
            $where .= " AND (
                ($wpdb->posts.post_author = {$author_id}) OR 
                (meta1.meta_key = 'ea_selected_author' AND meta1.meta_value = {$author_id}))";
        }
    
        // Reset post_author to prevent conflicts with the author title in the loop.
        add_filter('the_posts', array($this, 'authorsy_reset_post_author'), 10, 2);
    
        return $where;
    }
    
    /**
     * A function to reset the post author for a given set of posts based on the provided query.
     *
     * @param array $posts The array of posts to reset the post author for.
     * @param WP_Query $query The query object used to determine the new post author.
     * @return array The updated array of posts with the post author reset.
     */
    public function authorsy_reset_post_author( $posts, $query ) {
        if ( $query->is_author() && $query->is_main_query() && ! is_admin() ) {
            foreach ( $posts as &$post ) {
                $post->post_author = $query->get_queried_object_id();
            }
        }
    
        return $posts;
    }
   
    /**
     * A description of the entire PHP function.
     *
     * @param datatype $paramname description
     * @throws Some_Exception_Class description of exception
     * @return Some_Return_Value
     */
    public function authorsy_search_distinct()
    {
        return "DISTINCT";
    }

     /**
     * Enables author metabox classes.
     *
     * @param datatype $classes The original classes.
     * @throws None
     * @return datatype The updated classes.
     */
    public function enable_author_metabox_classes($classes)
    {
        $author_metabox = authorsy_get_settings(); 
        if ($author_metabox && $author_metabox['enable_multi_author'] == true) {
            $classes .= ' ea-enable-multi-author';
        } 
        return $classes;
       
    } 

  

}
