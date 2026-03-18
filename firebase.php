<?php
use Kreait\Firebase\Factory;

function sendFirebaseNotification($tokens, $title, $body, $data = []) {
    $factory = (new Factory)->withServiceAccount(__DIR__ . '/firebase-service-account.json'); 
    $messaging = $factory->createMessaging();

    $message = [
        'notification' => [
            'title' => $title,
            'body'  => $body,
        ],
        'data' => $data,
    ];

    foreach ($tokens as $token) {
        try {
            $messaging->sendMulticast([
                'tokens' => [$token],
                'notification' => $message['notification'],
                'data' => $message['data'],
            ]);
        } catch (\Exception $e) {
            error_log("Firebase send error: " . $e->getMessage());
        }
    }
}
