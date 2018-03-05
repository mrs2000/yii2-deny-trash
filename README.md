yii2-deny-trash
=================

Adds a ban on access by ip address, in accordance with the rules

Installation
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
php composer.phar require --prefer-dist mrssoft/yii2-deny-trash "*"
```

or add

```
"mrssoft/yii2-deny-trash": "*"
```

to the require section of your `composer.json` file.


Usage
-----

Configuration:

```php
'components' => [
    ...
    'log' => [
        'targets' => [
        [
            'class' => 'mrssoft\denytrash\DenyTrashTarget',
            'levels' => ['error']
        ],
   ]
   ....
]
```

.htaccess:

```
...
order deny,allow
...
```

Setting rules
-------------

Setting rules in a file `options.json`