<?php

namespace mrssoft\denytrash;

use Yii;
use yii\log\Target;

class DenyTrashTarget extends Target
{
    /**
     * @var array
     */
    private $options;

    /**
     * Server type [Apache|Nginx]
     * @var string
     */
    public $serverType = 'Apache';

    /**
     * Path to config path
     * @var string
     */
    public $path;

    /**
     * @var array
     */
    public $excludeIp = [];

    public $maxRecords = 200;

    public function export()
    {
        foreach ($this->messages as $message) {
            $this->processMessage($message);
        }
    }

    private function loadOptions(): bool
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

            $this->options['exclude']['ip'] = array_merge($this->options['exclude']['ip'], $this->excludeIp);
        }

        return true;
    }

    private function processMessage(array $message)
    {
        if ($message[2] == 'yii\web\HttpException:404') {
            if ($this->loadOptions() === false) {
                return;
            }

            if (isset($this->options['deny']['uri'])) {
                $url = Yii::$app->request->url;
                foreach ($this->options['deny']['uri'] as $item) {
                    if (stripos($url, $item) !== false) {
                        $this->deny('uri[' . $item . '] ' . $url);
                        break;
                    }
                }
            }
        }
    }

    private function deny(string $comment = ''): void
    {
        $ip = Yii::$app->request->userIP;

        if ($this->checkIP($ip) && $this->checkBrowser(Yii::$app->request->userAgent)) {

            $this->{'deny' . $this->serverType}($ip, $comment);

            //Disable all log targets
            foreach (Yii::$app->log->targets as $target) {
                $target->enabled = false;
            }
        }
    }

    protected function denyApache(string $ip, string $comment): void
    {
        $path = Yii::getAlias('@webroot') . '/.htaccess';

        $fp = fopen($path, 'rb+');
        if ($fp && flock($fp, LOCK_EX)) {
            if (($data = fread($fp, filesize($path))) && preg_match('/#deny-trash-start\n(.*)#deny-trash-end/si', $data, $matches)) {
                $lines = $matches[1] ? explode("\n", $matches[1]) : [];
                $lines = array_map(static function ($e) {
                    return trim($e);
                }, $lines);
                $lock = "deny from $ip";
                if (in_array($lock, $lines) === false) {
                    $comment = $this->clear($comment);
                    $date = date('Y-m-d H:i:s');
                    $lines = array_filter($lines, static function ($e) {
                        return empty($e) === false;
                    });
                    $lines = array_splice($lines, count($lines) - $this->maxRecords, $this->maxRecords);
                    $lines[] = "#$ip - $date - $comment";
                    $lines[] = $lock;
                    $data = preg_replace('/(#deny-trash-start\n)(.*)(#deny-trash-end)/si', '$1' . implode("\n", $lines) . "\n$3", $data);
                    ftruncate($fp, 0);
                    fseek($fp, 0);
                    fwrite($fp, $data, strlen($data));
                }
            }
            fflush($fp);
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    protected function denyNginx(string $ip, string $comment): void
    {
        $fp = fopen($this->path, 'ab');
        if ($fp && flock($fp, LOCK_EX)) {
            $data = "\r\ndeny $ip; # $comment";
            fwrite($fp, $data, strlen($data));
            fflush($fp);
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    private function clear(string $string): string
    {
        return str_replace([':', '/'], [';', "\\"], $string);
    }

    private function checkIP(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) && (!isset($this->options['exclude']['ip']) || !in_array($ip, $this->options['exclude']['ip'], true));
    }

    private function checkBrowser(?string $userAgent): bool
    {
        if ($userAgent && isset($this->options['exclude']['browser'])) {
            foreach ($this->options['exclude']['browser'] as $browser) {
                if (mb_strpos($userAgent, $browser) !== false) {
                    return false;
                }
            }
        }

        return true;
    }
}