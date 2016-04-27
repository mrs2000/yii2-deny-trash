<?
namespace mrssoft\denytrash;

use Yii;
use yii\log\Target;

class DenyTrashTarget extends Target
{
    private $options;

    public function export()
    {
        foreach ($this->messages as $message) {
            $this->processMessage($message);
        }
    }

    private function loadOptions()
    {
        if ($this->options === null) {
            $file = __DIR__ . '/options.json';

            if (!is_file($file)) {
                return false;
            }
            $this->options = @json_decode(@file_get_contents($file), true);
            if (!is_array($this->options)) {
                return false;
            }
        }

        return true;
    }

    private function processMessage($message)
    {
        if ($message[2] == 'yii\web\HttpException:404') {
            if ($this->loadOptions() === false) {
                return;
            }

            $url = Yii::$app->request->url;

            if (isset($this->options['deny']['uri'])) {
                foreach ($this->options['deny']['uri'] as $item) {
                    if (stripos($url, $item) !== false) {
                        $this->deny('uri[' . $item  .'] ' . $url);
                        break;
                    }
                }
            }
        }
    }

    private function deny($comment = '')
    {
        $ip = Yii::$app->request->userIP;
        $userAgent = Yii::$app->request->userAgent;
        
        if ($this->checkIP($ip) && $this->checkBrowser($userAgent)) {

            $path = Yii::getAlias('@webroot') . '/.htaccess';

            $fp = fopen($path, 'r+');
            if ($fp && flock($fp, LOCK_EX)) {
                if ($data = fread($fp, filesize($path))) {
                    $comment = $this->clear($comment);
                    foreach (['/(order[a-zA-Z ,]*)[\r\n]/Umi'] as $pattern) {
                        if (preg_match($pattern, $data)) {
                            $data = preg_replace($pattern, "$1\r\ndeny from $ip # $comment\r", $data);
                            ftruncate($fp, 0);
                            fseek($fp, 0);
                            fwrite($fp, $data, strlen($data));
                            break;
                        }
                    }
                }
                fflush($fp);
                flock($fp, LOCK_UN);
                fclose($fp);
            }
        }
    }

    private function clear($string)
    {
        return str_replace([':', '/'], [';', "\\"], $string);
    }

    private function checkIP($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP) &&
               (!isset($this->options['exclude']['ip']) || !in_array($ip, $this->options['exclude']['ip'], true));
    }

    private function checkBrowser($userAgent)
    {
        if (isset($this->options['exclude']['browser'])) {
            foreach ($this->options['exclude']['browser'] as $browser) {
                if (mb_strpos($userAgent, $browser) !== false) {
                    return false;
                }
            }
        }

        return true;
    }
}