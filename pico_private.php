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

    public function onConfigLoaded(&$config) {
        $this->config = $config["pico_private"];
        $this->users = $this->config['users'];

        $this->theme = $config['theme'];
        $this->base_url = $config['base_url'];

        session_name('pico_private_'. str_replace(' ', '_', strtolower($config["site_title"])));
        $this->persistSession();
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
            if($_COOKIE['persist_session'] !== true) { session_unset(); }
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
    }

    public function onPageRendering(Twig_Environment $twig, array &$twigVariables, &$template) {

        if((!isset($_SESSION['authed']) || $_SESSION['authed'] == false) && $this->config['private'] == "all") {
            $this->handleLogin($twigVariables, $twig, $template);
        }

        if((!isset($_SESSION['authed']) || $_SESSION['authed'] == false) && $this->config['private'] == "meta" && $this->privatePage == true) {
            $twigVariables['redirect_url'] = "/" . $this->url;
            $this->handleLogin($twigVariables, $twig, $template);
        }

        if(isset($_SESSION['authed'])) {
            $twigVariables['authed'] = $_SESSION['authed'];
            $twigVariables['username'] =  $_SESSION['username'];
        }

        $twigVariables['session'] = $_SESSION;
    }

    private function redirect($url) {
        header('Location: '. $this->base_url . $url);
        exit;
    }

    private function handleLogin(&$twigVariables) {
        if(isset($_POST['username'])) {
            $postUsername = $_POST['username'];
        }
        if(isset($_POST['password'])) {
            $postPassword = $_POST['password'];
        }
        $postPersistSession = (is_null($_POST['persist_session']) ? false : true);

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

                $this->persistSession($postPersistSession);

                if(isset($_POST['redirect_url'])) {
                    $this->redirect($_POST['redirect_url']);
                }
                $this->redirect('/');
            } else {
                $twigVariables['login_error'] = 'Invalid login';
                $twigVariables['username'] = $postUsername;
                $twigVariables['persist_session'] = $postPersistSession;
            }
        }

        header($_SERVER['SERVER_PROTOCOL'].' 200 OK');
        $themesDir = $this->getPico()->getThemesDir();

        $twigVariables['meta']['title'] = "Login";

        $loginFile = $themesDir . $this->theme . "/login";

        if ( file_exists($loginFile . ".twig") ) {
            echo $this->getTwig()->render("login.twig", $twigVariables);
        } else if( file_exists($loginFile . ".html") ) {
            echo $this->getTwig()->render("login.html", $twigVariables);
        } else if( file_exists($loginFile . ".htm") ) {
            echo $this->getTwig()->render("login.htm", $twigVariables);
        } else {
            echo '<h1>Pico private error</h1>';
            echo '<h2>No "login.html" or "login.twig" file found in theme ' . $this->theme;
        }
        exit;
    }

    // create, renew, or destroy the session
    private function persistSession($setTo = null) {
        $expire = 0;

        if($setTo === false) { $expire = 0; }
        else if( $setTo === true || (isset($_COOKIE['persist_session']) && $_COOKIE['persist_session'] === true) ) {
            $expire = $this->getSessionPersistTime();
        }

        $twigVariables['persist_session'] = ($expire > 0 ? true : false);

        if($setTo === true) {
            $twigVariables['persist_session'] = true;
            session_set_cookie_params($expire, '/',$this->base_url, true, true);
        } else {
            $twigVariables['persist_session'] = false;
        }
        setcookie('persist_session', $twigVariables['persist_session'], $expire, '/', $this->base_url, true, true);
        session_start();
    }

    // Gets the time a session should expire if it's set to persist
    private function getSessionPersistTime() {
        $persist_for = 2592000; // default persist time in seconds (1 month)
        if( isset($this->config['stay_logged_in_time']) && intval($this->config['stay_logged_in_time']) > 0 ) {
            $persist_for = intval($this->config['stay_logged_in_time']);
        }

        return time() + $persist_for;
    }

}
