<?php

/**
 * Admin meni class
 *
 * @package Authorsy
 */

namespace Authorsy\Core\Admin;
defined( 'ABSPATH' ) || exit;
/**
 * Class Menu
 */
class Menu
{

    use \Authorsy\Utils\Singleton;

    /**
     * Initialize
     *
     * @return void
     */
    public function init()
    {
        add_action('admin_menu', array($this, 'register_admin_menu'));

       
    }


    /**
     * Register admin menu
     *
     * @return void
     */

    public function register_admin_menu()
    {
        global $submenu;
        $capability = 'manage_options';
        $slug       = 'authorsy';
        $url        = 'admin.php?page=' . $slug . '#';
        $menu_items = array(
         
            [
                'id'         => 'author',
                'title'      => esc_html__('Authors', 'authorsy'),
                'link'       => '/author',
                'capability' => 'manage_options',
                'position'   => 2,
            ], 
            
            [
                'id'         => 'settings',
                'title'      => esc_html__('Settings', 'authorsy'),
                'link'       => '/settings',
                'capability' => 'manage_options',
                'position'   => 3,
            ], 
            [
                'id'         => 'shortcodes',
                'title'      => esc_html__('Shortcodes', 'authorsy'),
                'link'       => '/shortcodes',
                'capability' => 'manage_options',
                'position'   => 4,
            ], 
           
        );

        add_menu_page(
            esc_html__('Authorsy', 'authorsy'),
            esc_html__('Authorsy', 'authorsy'),
            $capability,
            $slug,
            array($this, 'authorsy_dashboard_view'),
            "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIGZpbGw9IiNmZmZmZmYiIHZpZXdCb3g9IjAgMCA2NDAgNTEyIj48IS0tISBGb250IEF3ZXNvbWUgUHJvIDYuNC4yIGJ5IEBmb250YXdlc29tZSAtIGh0dHBzOi8vZm9udGF3ZXNvbWUuY29tIExpY2Vuc2UgLSBodHRwczovL2ZvbnRhd2Vzb21lLmNvbS9saWNlbnNlIChDb21tZXJjaWFsIExpY2Vuc2UpIENvcHlyaWdodCAyMDIzIEZvbnRpY29ucywgSW5jLiAtLT48cGF0aCBkPSJNMjI0IDBhMTI4IDEyOCAwIDEgMSAwIDI1NkExMjggMTI4IDAgMSAxIDIyNCAwek0xNzguMyAzMDRoOTEuNGMxMS44IDAgMjMuNCAxLjIgMzQuNSAzLjNjLTIuMSAxOC41IDcuNCAzNS42IDIxLjggNDQuOGMtMTYuNiAxMC42LTI2LjcgMzEuNi0yMCA1My4zYzQgMTIuOSA5LjQgMjUuNSAxNi40IDM3LjZzMTUuMiAyMy4xIDI0LjQgMzNjMTUuNyAxNi45IDM5LjYgMTguNCA1Ny4yIDguN3YuOWMwIDkuMiAyLjcgMTguNSA3LjkgMjYuM0gyOS43QzEzLjMgNTEyIDAgNDk4LjcgMCA0ODIuM0MwIDM4My44IDc5LjggMzA0IDE3OC4zIDMwNHpNNDM2IDIxOC4yYzAtNyA0LjUtMTMuMyAxMS4zLTE0LjhjMTAuNS0yLjQgMjEuNS0zLjcgMzIuNy0zLjdzMjIuMiAxLjMgMzIuNyAzLjdjNi44IDEuNSAxMS4zIDcuOCAxMS4zIDE0Ljh2MzAuNmM3LjkgMy40IDE1LjQgNy43IDIyLjMgMTIuOGwyNC45LTE0LjNjNi4xLTMuNSAxMy43LTIuNyAxOC41IDIuNGM3LjYgOC4xIDE0LjMgMTcuMiAyMC4xIDI3LjJzMTAuMyAyMC40IDEzLjUgMzFjMi4xIDYuNy0xLjEgMTMuNy03LjIgMTcuMmwtMjUgMTQuNGMuNCA0IC43IDguMSAuNyAxMi4zcy0uMiA4LjItLjcgMTIuM2wyNSAxNC40YzYuMSAzLjUgOS4yIDEwLjUgNy4yIDE3LjJjLTMuMyAxMC42LTcuOCAyMS0xMy41IDMxcy0xMi41IDE5LjEtMjAuMSAyNy4yYy00LjggNS4xLTEyLjUgNS45LTE4LjUgMi40bC0yNC45LTE0LjNjLTYuOSA1LjEtMTQuMyA5LjQtMjIuMyAxMi44bDAgMzAuNmMwIDctNC41IDEzLjMtMTEuMyAxNC44Yy0xMC41IDIuNC0yMS41IDMuNy0zMi43IDMuN3MtMjIuMi0xLjMtMzIuNy0zLjdjLTYuOC0xLjUtMTEuMy03LjgtMTEuMy0xNC44VjQ1NC44Yy04LTMuNC0xNS42LTcuNy0yMi41LTEyLjlsLTI0LjcgMTQuM2MtNi4xIDMuNS0xMy43IDIuNy0xOC41LTIuNGMtNy42LTguMS0xNC4zLTE3LjItMjAuMS0yNy4ycy0xMC4zLTIwLjQtMTMuNS0zMWMtMi4xLTYuNyAxLjEtMTMuNyA3LjItMTcuMmwyNC44LTE0LjNjLS40LTQuMS0uNy04LjItLjctMTIuNHMuMi04LjMgLjctMTIuNEwzNDMuOCAzMjVjLTYuMS0zLjUtOS4yLTEwLjUtNy4yLTE3LjJjMy4zLTEwLjYgNy43LTIxIDEzLjUtMzFzMTIuNS0xOS4xIDIwLjEtMjcuMmM0LjgtNS4xIDEyLjQtNS45IDE4LjUtMi40bDI0LjggMTQuM2M2LjktNS4xIDE0LjUtOS40IDIyLjUtMTIuOVYyMTguMnptOTIuMSAxMzMuNWE0OC4xIDQ4LjEgMCAxIDAgLTk2LjEgMCA0OC4xIDQ4LjEgMCAxIDAgOTYuMSAweiIvPjwvc3ZnPg==",
            65
        );

  

        $menu_items = apply_filters('authorsy_menu', $menu_items);
        $position   = array_column($menu_items, 'position');

        array_multisort($position, SORT_ASC, $menu_items);

        foreach ($menu_items as $item) {
            $submenu[$slug][] = [$item['title'], $item['capability'], $url . $item['link']]; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
        }
    }

    /**
     * Admin dashboard view
     *
     * @return void
     */
    public function authorsy_dashboard_view()
    {
?>
        <div class="wrap" id="authorsy_dashboard">
        </div>
<?php
    } 
}
