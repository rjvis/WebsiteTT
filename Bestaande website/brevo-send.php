<?php
/**
 * ============================================================================
 *  TOTAL TRAVEL — BREVO E-MAIL PROXY
 *  Backend-script voor het groepsvluchten-aanvraagformulier.
 *
 *  Wat dit script doet:
 *    1. Ontvangt JSON POST-data van het HTML-formulier.
 *    2. Verstuurt twee e-mails via de Brevo API (api.brevo.com/v3/smtp/email):
 *         a) De volledige aanvraag naar info@totaltravel.nl
 *         b) Een bevestiging naar de aanvrager
 *    3. Antwoordt met JSON: { "success": true } of { "success": false, "error": "..." }
 *
 *  WAAROM EEN PHP-PROXY?
 *  De Brevo API-sleutel mag NOOIT in JavaScript/HTML staan — dat is publiek
 *  zichtbaar in de broncode en kan misbruikt worden. Dit PHP-bestand draait
 *  op uw eigen server; alleen daar staat de sleutel.
 *
 *  INSTALLATIE
 *    1. Pas hieronder onder CONFIG de waarden aan (API-sleutel, afzender,
 *       toegestane CORS-origin).
 *    2. Upload dit bestand naar een PHP-locatie op uw server,
 *       bijv. https://totaltravel.nl/api/brevo-send.php
 *    3. Zet in het HTML-formulier CONFIG.backendUrl op datzelfde pad.
 *    4. Zorg dat uw verzenddomein bij Brevo geverifieerd is (SPF/DKIM/DMARC),
 *       anders worden mails geblokkeerd of in spam terechtkomen.
 *
 *  BEVEILIGING
 *    - API-sleutel staat alleen server-side.
 *    - CORS-header beperkt welke websites dit endpoint mogen aanroepen.
 *    - Honeypot-controle filtert simpele bot-submissies.
 *    - Rate-limiting per IP (eenvoudig, op bestandsbasis).
 *    - Server-side validatie van verplichte velden.
 *
 *  VEREIST: PHP 7.4+ met cURL-extensie (standaard aanwezig op vrijwel
 *  alle hostings).
 * ============================================================================
 */

// =============================================================
// CONFIG — pas deze waarden aan
// =============================================================
$CONFIG = [

    // ✅ Uw Brevo API-sleutel (begint met "xkeysib-...")
    //    Aan te maken in Brevo: Settings → SMTP & API → API Keys → Generate
    'brevo_api_key' => 'xkeysib-VUL-HIER-UW-SLEUTEL-IN',

    // ✅ Afzender — moet een geverifieerd e-mailadres op uw geverifieerd
    //    Brevo-domein zijn.
    'sender_email'  => 'info@totaltravel.nl',
    'sender_name'   => 'Total Travel',

    // ✅ Logo in de e-mails. Vul een PUBLIEK bereikbare URL in naar uw logo
    //    (bijv. 'https://totaltravel.nl/wp-content/uploads/2024/logo.png').
    //    De afbeelding moet online staan — e-mailclients tonen geen lokale
    //    bestanden. Laat leeg ('') om in plaats daarvan de tekst "Total Travel"
    //    in de huisstijl te tonen.
    'logo_url'      => 'https://totaltravel.nl/wp-content/uploads/2026/04/Logo-zonder-pay-off.png',
    // Maximale weergavebreedte van het logo in pixels.
    'logo_width'    => 180,

    // ✅ Ontvanger van de aanvragen (intern)
    'recipient_email' => 'info@totaltravel.nl',
    'recipient_name'  => 'Total Travel',

    // ✅ Welke website(s) mogen dit endpoint aanroepen?
    //    Vul exact in (zonder pad), bijv. 'https://totaltravel.nl'
    //    Of meerdere: ['https://totaltravel.nl', 'https://www.totaltravel.nl']
    'allowed_origins' => [
        'https://totaltravel.nl',
        'https://www.totaltravel.nl',
    ],

    // Rate limit: max aantal submissies per IP per uur
    'rate_limit_per_hour' => 10,

    // Tijdelijke map voor rate-limit-bestanden (moet schrijfbaar zijn)
    'rate_limit_dir' => sys_get_temp_dir() . '/tt_ratelimit',
];

// =============================================================
// CORS & request-controles
// =============================================================
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $CONFIG['allowed_origins'], true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Accept');
header('Content-Type: application/json; charset=utf-8');

// Preflight OPTIONS afhandelen
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond(false, 'Alleen POST is toegestaan', 405);
}

// Origin moet bekend zijn
if (!empty($origin) && !in_array($origin, $CONFIG['allowed_origins'], true)) {
    respond(false, 'Origin niet toegestaan', 403);
}

// =============================================================
// Body lezen
// =============================================================
$raw = file_get_contents('php://input');
$payload = json_decode($raw, true);
if (!is_array($payload)) {
    respond(false, 'Ongeldige JSON', 400);
}

$data        = $payload['data']        ?? null;
$subject     = trim((string)($payload['subject'] ?? ''));
$adminBody   = (string)($payload['adminBody']   ?? '');
$confirmBody = (string)($payload['confirmBody'] ?? '');

if (!is_array($data) || $subject === '' || $adminBody === '' || $confirmBody === '') {
    respond(false, 'Ontbrekende velden in payload', 400);
}

// =============================================================
// Honeypot — sommige bots vullen alle velden, ook verborgen
// =============================================================
if (!empty($data['website']) || !empty($data['_honeypot'])) {
    respond(true, null); // doen alsof het verzonden is, maar niets doen
}

// =============================================================
// Server-side validatie van verplichte velden
// =============================================================
$verplicht = ['aanvragerType', 'vluchtType', 'bestemming', 'vertrekdatum',
              'voornaam', 'achternaam', 'email', 'telefoon'];
foreach ($verplicht as $f) {
    if (empty(trim((string)($data[$f] ?? '')))) {
        respond(false, "Verplicht veld ontbreekt: $f", 400);
    }
}

$email = trim((string)$data['email']);
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    respond(false, 'Ongeldig e-mailadres', 400);
}

// Minstens één vertrekluchthaven
$airports = $data['vertrekluchthavens'] ?? [];
if (!is_array($airports) || count(array_filter($airports, function ($a) {
        return !empty(trim((string)($a['name'] ?? '')));
    })) === 0) {
    respond(false, 'Ten minste één vertrekluchthaven verplicht', 400);
}

// =============================================================
// Rate-limit per IP
// =============================================================
if (!enforceRateLimit($CONFIG)) {
    respond(false, 'Te veel aanvragen — probeer het over een uur opnieuw', 429);
}

// =============================================================
// HTML-versies van de e-mail body opbouwen
// (Brevo accepteert htmlContent of textContent — we sturen beide
//  zodat clients zonder HTML-weergave ook de tekstversie zien.)
// =============================================================
$adminHtml   = bodyToHtml($adminBody, $CONFIG, false);
$confirmHtml = bodyToHtml($confirmBody, $CONFIG, true);

$voornaam   = trim((string)$data['voornaam']);
$achternaam = trim((string)$data['achternaam']);
$volledigeNaam = trim($voornaam . ' ' . $achternaam);

// =============================================================
// E-mail 1: aanvraag naar info@totaltravel.nl
// =============================================================
$result1 = brevoSendEmail($CONFIG, [
    'sender'      => ['email' => $CONFIG['sender_email'], 'name' => $CONFIG['sender_name']],
    'to'          => [['email' => $CONFIG['recipient_email'], 'name' => $CONFIG['recipient_name']]],
    'replyTo'     => ['email' => $email, 'name' => $volledigeNaam],
    'subject'     => $subject,
    'htmlContent' => $adminHtml,
    'textContent' => $adminBody,
    'tags'        => ['groepsvlucht-aanvraag'],
]);
if (!$result1['ok']) {
    respond(false, 'Verzending naar info@totaltravel.nl mislukt: ' . $result1['error'], 502);
}

// =============================================================
// E-mail 2: bevestiging naar aanvrager
// =============================================================
$result2 = brevoSendEmail($CONFIG, [
    'sender'      => ['email' => $CONFIG['sender_email'], 'name' => $CONFIG['sender_name']],
    'to'          => [['email' => $email, 'name' => $volledigeNaam]],
    'replyTo'     => ['email' => $CONFIG['recipient_email'], 'name' => $CONFIG['recipient_name']],
    'subject'     => 'Bevestiging groepsvlucht-aanvraag — Total Travel',
    'htmlContent' => $confirmHtml,
    'textContent' => $confirmBody,
    'tags'        => ['groepsvlucht-bevestiging'],
]);
// Als bevestiging faalt: niet kritiek — aanvraag is wel binnen.
// We loggen wel maar laten het formulier toch succesvol zijn.
if (!$result2['ok']) {
    error_log('[TT Brevo] Bevestiging mailen mislukt: ' . $result2['error']);
}

respond(true, null);

// =============================================================
// HELPER FUNCTIES
// =============================================================

/**
 * Verstuur één e-mail via de Brevo API.
 *
 * @param array $cfg     CONFIG-array
 * @param array $payload Brevo-payload (sender/to/subject/...)
 * @return array         ['ok' => bool, 'error' => string|null]
 */
function brevoSendEmail(array $cfg, array $payload): array
{
    $ch = curl_init('https://api.brevo.com/v3/smtp/email');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_UNICODE),
        CURLOPT_HTTPHEADER     => [
            'accept: application/json',
            'content-type: application/json',
            'api-key: ' . $cfg['brevo_api_key'],
        ],
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_CONNECTTIMEOUT => 10,
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        return ['ok' => false, 'error' => 'cURL-fout: ' . $curlErr];
    }

    if ($code >= 200 && $code < 300) {
        return ['ok' => true, 'error' => null];
    }

    $decoded = json_decode($body, true);
    $msg = is_array($decoded) && isset($decoded['message'])
        ? $decoded['message']
        : 'HTTP ' . $code . ' — ' . substr($body, 0, 200);
    return ['ok' => false, 'error' => $msg];
}

/**
 * Converteer plain-text body naar eenvoudige HTML met behoud van regels.
 */
function bodyToHtml(string $text, array $cfg, bool $isConfirmation = false): string
{
    $esc = htmlspecialchars($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    // Maak section headers (regels die met ── beginnen) vetgedrukt
    $esc = preg_replace('/^(── [^\n]+)$/m', '<strong style="color:#a0522d">$1</strong>', $esc);

    // Header: logo indien ingesteld, anders tekst "Total Travel"
    $logoUrl   = trim((string)($cfg['logo_url'] ?? ''));
    $logoWidth = (int)($cfg['logo_width'] ?? 180);
    if ($logoUrl !== '') {
        $header = '<div style="border-bottom:2px solid #a0522d;padding-bottom:14px;margin-bottom:18px;">'
                . '<img src="' . htmlspecialchars($logoUrl, ENT_QUOTES, 'UTF-8') . '" '
                . 'alt="Total Travel" width="' . $logoWidth . '" '
                . 'style="display:block;border:0;outline:none;text-decoration:none;max-width:' . $logoWidth . 'px;height:auto;">'
                . '</div>';
    } else {
        $header = '<div style="border-bottom:2px solid #a0522d;padding-bottom:14px;margin-bottom:18px;'
                . 'font-family:Georgia,serif;font-size:22px;font-style:italic;color:#a0522d;">Total Travel</div>';
    }

    $html  = '<div style="font-family:DM Sans,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.7;color:#2c1f0e;max-width:600px;margin:0 auto;padding:20px;">';
    $html .= $header;
    $html .= '<pre style="font-family:DM Sans,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.7;white-space:pre-wrap;margin:0;color:#2c1f0e;">' . $esc . '</pre>';
    // Footer (dunne lijn + bedrijfsregel) alleen tonen bij de interne admin-mail,
    // niet bij de bevestiging aan de aanvrager.
    if (!$isConfirmation) {
        $html .= '<div style="margin-top:24px;padding-top:14px;border-top:1px solid #e0d2b8;font-size:11px;color:#8a6d52;">Total Travel · T: +31 78 681 75 79 · info@totaltravel.nl</div>';
    }
    $html .= '</div>';
    return $html;
}

/**
 * Eenvoudige rate-limit per IP op bestandsbasis.
 * Returns true als verzoek mag doorgaan, false als de limiet overschreden is.
 */
function enforceRateLimit(array $cfg): bool
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $dir = $cfg['rate_limit_dir'];
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    if (!is_dir($dir) || !is_writable($dir)) {
        return true; // bij twijfel toestaan
    }
    $file = $dir . '/' . sha1($ip) . '.json';
    $now = time();
    $window = 3600;
    $entries = [];
    if (is_file($file)) {
        $entries = json_decode((string)@file_get_contents($file), true) ?: [];
        $entries = array_filter($entries, function ($t) use ($now, $window) {
            return ($now - $t) < $window;
        });
    }
    if (count($entries) >= $cfg['rate_limit_per_hour']) {
        return false;
    }
    $entries[] = $now;
    @file_put_contents($file, json_encode(array_values($entries)));
    return true;
}

/**
 * Geef JSON-antwoord en stop.
 */
function respond(bool $success, ?string $error = null, int $httpCode = 200): void
{
    http_response_code($httpCode);
    $out = ['success' => $success];
    if ($error !== null) $out['error'] = $error;
    echo json_encode($out, JSON_UNESCAPED_UNICODE);
    exit;
}
