<?php

namespace mrssoft\denytrash;

use Yii;
use yii\base\Exception;
use yii\web\Controller;
use yii\web\HttpException;

/**
 * Update component options
 * Class UpdateController
 * @package mrssoft\denytrash
 */
class UpdateController extends Controller
{
    public $enableCsrfValidation = false;

    public function actionIndex()
    {
        if (Yii::$app->request->isPost === false) {
            throw new HttpException(400);
        }

        $data = file_get_contents('php://input');
        if (empty($data)) {
            throw new HttpException(400, 'Data is empty.');
        }

        try {
            $json = json_decode($data);
            if ($json === null) {
                throw new HttpException(400, 'Invalid data.');

            }
        } catch (Exception $e) {
            throw new HttpException(400, 'Invalid data. ' . $e->getMessage());
        }

        $path = __DIR__ . '/options.json';
        if (is_writable($path) && @file_put_contents($path, $data) === false) {
            throw new HttpException(400, 'Error update options.');
        }

        echo 'SUCCESS';
        Yii::$app->end();
    }
}