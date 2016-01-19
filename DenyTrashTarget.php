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

            if (isset($this->options['uri'])) {
                foreach ($this->options['uri'] as $item) {
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
        if ($this->checkIP($ip)) {

            $path = Yii::getAlias('@webroot') . '/.htaccess';
            $data = file_get_contents($path);
            $comment = $this->clear($comment);

            foreach (['/(order[a-zA-Z ,]*)[\r\n]/Umi'] as $pattern) {
                if (preg_match($pattern, $data)) {
                    $data = preg_replace($pattern, "$1\r\ndeny from $ip # $comment\r", $data);
                    file_put_contents($path, $data);
                    break;
                }
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
               (!isset($this->options['exclude']) || !in_array($ip, $this->options['exclude'], true));
    }
}