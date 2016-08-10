<?php

/**
 * A plugin that let you create a private Pico with authentication form
 *
 * @author Johan BLEUZEN
 * @link http://www.johanbleuzen.fr
 * @license http://opensource.org/licenses/MIT
 */
class Pico_Private extends AbstractPicoPlugin {

    private $config;

    private $users;

    private $url;

    private $theme;

    private $base_url;

    private $privatePage;

    public function onPluginsLoaded() {
        session_start();
    }

    public function onConfigLoaded(&$settings) {
        $this->config = $settings["pico_private"];
        $this->users = $this->config['users'];

        $this->theme = $settings['theme'];
        $this->base_url = $settings['base_url'];
    }

    public function onRequestUrl(&$url) {
        $this->url = $url;
        if($this->config['private'] == 'all') {

            if($url == 'login') {
                if(! isset($_SESSION['authed']) || $_SESSION['authed'] == false) {
                    return;
                } else {
                    $this->redirect('/');
                    exit;
                }
            }

            if(!isset($_SESSION['authed']) || $_SESSION['authed'] == false) {
                $this->redirect('/login');
            }
        }
        if($url == 'logout') {
            session_destroy();
            $this->redirect('/');
        }
    }

    public function onMetaParsed(&$meta) {
        if(in_array('private', $meta)) {
            $this->privatePage = $meta['private'];
        } else {
            $this->privatePage = false;
        }

        // todo
        //$this->privatePage = (in_array('private', $meta) ?  $meta['private'] : false);
    }

    public function onPageRendering(&$twig_vars, &$twig) {

        if((!isset($_SESSION['authed']) || $_SESSION['authed'] == false) && $this->config['private'] == "all") {
            $this->handleLogin($twig_vars, $twig);
        }

        if((!isset($_SESSION['authed']) || $_SESSION['authed'] == false) && $this->config['private'] == "meta" && $this->privatePage == true) {
            $twig_vars->redirect_url = "/" . $this->url;
            $this->handleLogin($twig_vars, $twig);
        }

        if(isset($_SESSION['authed'])) {
            $twig_vars['authed'] = $_SESSION['authed'];
            $twig_vars['username'] =  $_SESSION['username'];
        }
    }

    private function redirect($url) {
        header('Location: '. $this->base_url . $url);
        exit;
    }

    private function handleLogin($twig_vars, $twig) {
        if(isset($_POST['username'])) {
            $postUsername = $_POST['username'];
        }
        if(isset($_POST['password'])) {
            $postPassword = $_POST['password'];
        }

        if(!empty($postUsername) && !empty($postPassword)) {
            $authenticated = false;
            if($this->config['hash_type'] == 'sha1') {
                if(isset($this->users[$postUsername]) == true && ($this->users[$postUsername] == sha1($postPassword))) {
                    $authenticated = true;
                }
            } else if($this->config['hash_type'] == 'bcrypt') {
                if(isset($this->users[$postUsername]) == true && password_verify($postPassword, $this->users[$postUsername])) {
                    $authenticated = true;
                }
            }

            if($authenticated == true) {
                $_SESSION['authed'] = true;
                $_SESSION['username'] = $postUsername;
                if(isset($_POST['redirect_url'])) {
                    $this->redirect($_POST['redirect_url']);
                }
                $this->redirect('/');
            } else {
                $twig_vars['login_error'] = 'Invalid login';
                $twig_vars['username'] = $postUsername;
            }
        }

        header($_SERVER['SERVER_PROTOCOL'].' 200 OK');
        $loader = new Twig_Loader_Filesystem($twig['theme_dir']);
        $twig_login = new Twig_Environment($loader, $twig_vars);
        $twig_vars['meta']['title'] = "Login";
        if(file_exists($twig['theme_dir'] . "/login.html")) {
            echo $twig_login->render('login.html', $twig_vars);
        } else if (file_exists($twig['theme_dir'] . "/login.twig")) {
            echo $twig_login->render('login.twig', $twig_vars);
        } else {
            echo '<h1>Pico private error</h1>';
            echo '<h2>No "login.html" or "login.twig" file found in theme ' . $this->theme;
        }
        exit;
    }

}
