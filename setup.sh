#!/bin/bash

#Déclaration des variables globales (effets du texte)
GRAS="\e[1m"
VERT="\e[32m"
ROUGE="\e[31m"
BLEU="\e[34m"
RESET="\e[0m"
# Déclaration des variables globales (stockage des résultats)
DETECTED_PM=""
DETECTED_FW=""
DETECTED_WS=""
DETECTED_DNS=""
DETECTED_SSH=""
DETECTED_MAIL=""
DETECTED_MSG=""
DETECTED_NFS=""
DETECTED_MONITOR=""


#---------------------------------------------
#----------Déclaration des fonctions de config

config_all() {
    config_ip
    config_services
    config_firewall
    config_ssh
    config_dns
    config_web
    config_mail
    config_ntp
    config_nfs
}

config_ip() {
    echo "Veuillez entrer l'adresse IP que vous souhaitez configurer pour ce serveur (ex: 192.168.0.2) :"
    read -r choice_ip

    # Validation de l'adresse IP saisie par l'utilisateur
    if [[ "$choice_ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        octet1=${BASH_REMATCH[1]}
        octet2=${BASH_REMATCH[2]}
        octet3=${BASH_REMATCH[3]}
        octet4=${BASH_REMATCH[4]}

        # Vérification que chaque octet est bien compris entre 0 et 255
        if (( octet1 >= 0 && octet1 <= 255 && octet2 >= 0 && octet2 <= 255 && octet3 >= 0 && octet3 <= 255 && octet4 >= 0 && octet4 <= 255 )); then

            # Extraction des trois premiers octets et du dernier octet
            ip_base="${octet1}.${octet2}.${octet3}"
            last_octet=$octet4

            # Incrémentation du dernier octet
            if (( last_octet < 255 )); then
                ((backup_octet = last_octet + 1))
            else
                echo "Impossible d'incrémenter l'adresse IP car le dernier octet est déjà à sa valeur maximale (255)."
                ask_user_ip
                return
            fi
            
            # Construction de l'adresse IP du serveur de backup
            backup_ip="${ip_base}.${backup_octet}"

            echo "Votre adresse IP a été configurée sur $choice_ip."
            echo "L'adresse IP du serveur de backup tiers est $backup_ip."

            # Configuration de l'adresse IP sur l'interface réseau
            echo "Veuillez entrer le nom de votre interface réseau (ex: eth0, enp0s3, ens33) :"
            read -r network_interface

            # Configuration temporaire (change l'adresse IP immédiatement)
            ip addr add "$choice_ip/24" dev "$network_interface"
            ip link set "$network_interface" up

            # Configuration persistante (à ajouter à /etc/netplan/ ou /etc/network/interfaces selon la distribution)
            if [ -d /etc/netplan ]; then
                tee /etc/netplan/99-custom-config.yaml > /dev/null <<EOF
network:
  version: 2
  ethernets:
    $network_interface:
      dhcp4: no
      addresses: [$choice_ip/24]
      gateway4: ${ip_base}.1
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF
                netplan apply
                echo "Configuration persistante appliquée avec Netplan."
            elif [ -f /etc/network/interfaces ]; then
                tee -a /etc/network/interfaces > /dev/null <<EOF

auto $network_interface
iface $network_interface inet static
    address $choice_ip
    netmask 255.255.255.0
    gateway ${ip_base}.1
    dns-nameservers 1.1.1.1 8.8.8.8
EOF
                systemctl restart networking
                echo "Configuration persistante appliquée avec /etc/network/interfaces."
            else
                echo "Impossible de trouver un fichier de configuration réseau compatible."
            fi

            # Mise à jour de /etc/hosts
            if ! grep -q "$choice_ip" /etc/hosts; then
                echo "$choice_ip site.local" >> /etc/hosts
                echo "Entrée ajoutée à /etc/hosts : $choice_ip site.local"
            fi

            # Enregistrement dans des variables globales
            SERVER_IP="$choice_ip"
            BACKUP_IP="$backup_ip"
        else
            echo "L'adresse IP contient des valeurs d'octet hors de la plage autorisée (0-255). Veuillez réessayer."
            ask_user_ip
        fi
    else
        echo "Format d'adresse IP invalide. Veuillez entrer une adresse de la forme : X.X.X.X où X est un entier entre 0 et 255."
        ask_user_ip
    fi
}

config_services() {
    
    # Installer les paquets
    for package in "${packages[@]}"; do
            echo -e "Installation de $package avec $DETECTED_PM..."
            $DETECTED_PM install -y "$package"
    done

    # Démarrer les services
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            echo -e "Démarrage du service $service..."
            systemctl enable --now "$service"
        else
            echo -e "$service est déjà en cours d'exécution."
        fi
    done
}

config_firewall() {
    fw_command=""
    
    # Vérification du pare-feu détecté
    if [ "$DETECTED_FW" == "firewalld" ]; then
        fw_command="firewall-cmd"
    elif [ "$DETECTED_FW" == "ufw" ]; then
        fw_command="ufw"
    elif [ "$DETECTED_FW" == "iptables" ]; then
        fw_command="iptables"
    elif [ "$DETECTED_FW" == "pf" ]; then
        fw_command="pf"
    elif [ "$DETECTED_FW" == "nftables" ]; then
        fw_command="nft"
    else
        echo "Pare-feu non supporté : $DETECTED_FW"
        return 1
    fi
    
    # Retirer le port SSH par défaut (sécurité)
    $fw_command --permanent --remove-port=22/tcp

    # Ouvrir les ports nécessaires aux services
    for port in "${expected_ports[@]}"; do
        if [[ ! "$port" =~ ^[0-9]+$ ]]; then
            echo "Port invalide : $port"
            continue
        fi
        $fw_command --permanent --add-port="$port/tcp"
    done

    # Recharger la configuration du pare-feu
    $fw_command --reload
}

config_ssh() {
    # Sauvegarder le fichier de configuration avant modification
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Changer le port SSH et écouter sur toutes les interfaces
    sed -i 's/^#Port 22/Port 2025/' /etc/ssh/sshd_config
    sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config

    # Commenter les lignes inutiles liées à "ListenAddress"
    sed -i 's/^ListenAddress \*/#ListenAddress \*/' /etc/ssh/sshd_config
    sed -i 's/^#ListenAddress ::/ListenAddress ::/' /etc/ssh/sshd_config

    # Commenter les anciennes lignes de clé SSH
    sed -i 's/^#HostKey/ #HostKey/' /etc/ssh/sshd_config

    # Détection du service SSH actif
    if systemctl list-units --type=service | grep -q 'ssh.service'; then
        ssh_service_name="ssh"
    elif systemctl list-units --type=service | grep -q 'sshd.service'; then
        ssh_service_name="sshd"
    else
        echo "Impossible de détecter le nom du service SSH. Assurez-vous que SSH est installé."
        return 1
    fi

    # Redémarrer le service SSH
    if systemctl restart "$ssh_service_name"; then
        echo "Service SSH ($ssh_service_name) redémarré avec succès."
    else
        echo "Erreur lors du redémarrage du service SSH."
    fi

    echo "Service SSH configuré. Le port dédié est 2025."
}

config_dns() {

    # Détecter le nom du service dns et son répertoire
    case "$DETECTED_DNS" in
        "bind9")
            config_dir="/etc/bind"
            ;;
        "bind")
            config_dir="/var/lib/named"
            ;;
        "bind_utils")
            config_dir="/etc/named"
            ;;
        *)
            echo "Service DNS non reconnu : $DETECTED_DNS"
            return 1
            ;;
    esac

    # Sauvegarder les fichiers de configuration existants
    [ -f /etc/named.conf ] && cp /etc/named.conf /etc/named.conf.bak
    [ -f $config_dir/monsite.local.zone ] && cp $config_dir/monsite.local.zone $config_dir/monsite.local.zone.bak
    [ -f $config_dir/0.168.192.in-addr.arpa.zone ] && cp $config_dir/0.168.192.in-addr.arpa.zone $config_dir/0.168.192.in-addr.arpa.zone.bak

    # Configuration du fichier /etc/named.conf avec l'option forward only et autorisation de récursion
    tee /etc/named.conf > /dev/null <<EOF
options {
    directory "/var/lib/named";
    allow-query { any; };
    allow-recursion { any; };  # Autoriser la récursivité pour toutes les IP (à restreindre en production)
    recursion yes;
    forward only;
    forwarders {
        1.1.1.1;
        8.8.8.8;
    };
};

zone "monsite.local" IN {
    type master;
    file "/var/lib/named/monsite.local.zone";
};

zone "0.168.192.in-addr.arpa" IN {
    type master;
    file "/var/lib/named/0.168.192.in-addr.arpa.zone";
};
EOF

    # Configuration de la zone principale pour monsite.local
    tee /var/lib/named/monsite.local.zone > /dev/null <<EOF
\$TTL 86400
@   IN  SOA monsite.local. admin.monsite.local. (
        2025033101 ; Serial
        3600       ; Refresh
        1800       ; Retry
        604800     ; Expire
        86400 )    ; Minimum TTL

@       IN  NS  ns.monsite.local.
ns      IN  A   192.168.0.2    ; IP du serveur DNS
@       IN  A   192.168.0.2    ; IP du serveur Web
www     IN  A   192.168.0.2    ; Alias pour le serveur Web
EOF

    # Configuration de la zone reverse pour 192.168.0.x
    tee /var/lib/named/0.168.192.in-addr.arpa.zone > /dev/null <<EOF
\$TTL 86400
@   IN  SOA monsite.local. admin.monsite.local. (
        2025033101 ; Serial
        3600       ; Refresh
        1800       ; Retry
        604800     ; Expire
        86400 )    ; Minimum TTL

@       IN  NS  ns.monsite.local.
2       IN  PTR monsite.local.
EOF

    # Vérification de la configuration
    echo "Vérification de la configuration..."
    if named-checkconf /etc/named.conf && \
       named-checkzone monsite.local /var/lib/named/monsite.local.zone && \
       named-checkzone 0.168.192.in-addr.arpa /var/lib/named/0.168.192.in-addr.arpa.zone; then
        echo "La configuration est correcte."
    else
        echo "${ROUGE}Des erreurs ont été détectées dans la configuration. Merci de vérifier les fichiers.${RESET}"
        return 1
    fi

    # Redémarrer le service DNS
    echo "Redémarrage du service DNS..."
    if systemctl restart named.service; then
        echo "Serveur DNS configuré et service redémarré avec succès."
    else
        echo -e "${ROUGE}Erreur lors du redémarrage du service DNS. Consultez 'journalctl -xeu named.service' pour plus d'informations.${RESET}"
    fi
}

config_web() {

    echo "Configuration du serveur web..."

    # Détection du service Web (Apache)
    case "$DETECTED_WEB" in
        "apache2")
            config_dir="/etc/apache2"
            vhost_dir="$config_dir/vhosts.d"
            service_name="apache2"
            ;;
        "httpd")
            config_dir="/etc/httpd"
            vhost_dir="$config_dir/conf.d"
            service_name="httpd"
            ;;
        "httpd24")
            config_dir="/etc/httpd24"
            vhost_dir="$config_dir/conf.d"
            service_name="httpd24"
            ;;
        *)
            echo "Service Web non reconnu : $DETECTED_WEB"
            return 1
            ;;
    esac

    # Créer l'arborescence DocumentRoot si elle n'existe pas
    if [ ! -d "/var/www/site.local" ]; then
        mkdir -p /var/www/site.local
        echo "Arborescence /var/www/site.local créée."
    else
        echo "L'arborescence /var/www/site.local existe déjà."
    fi

    # Créer le fichier index.html s'il n'existe pas
    if [ ! -f "/var/www/site.local/index.html" ]; then
        echo "<h1>Test réussi !</h1>" > /var/www/site.local/index.html
        echo "Fichier index.html créé."
    else
        echo "Le fichier index.html existe déjà."
    fi

    # Attribution des permissions correctes
    chown -R wwwrun:www /var/www/site.local
    chmod -R 755 /var/www/site.local

    # Création du fichier de configuration du VirtualHost
    tee "$vhost_dir/site.local.conf" > /dev/null <<EOF
<VirtualHost *:80>
    ServerName site.local
    ServerAlias www.site.local
    DocumentRoot /var/www/site.local

    <Directory /var/www/site.local>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog /var/log/apache2/site.local-error.log
    CustomLog /var/log/apache2/site.local-access.log combined
</VirtualHost>
EOF

    # Activation du site si nécessaire (Pour Debian/Ubuntu seulement)
    if [ "$DETECTED_WEB" == "apache2" ]; then
        if ! apache2ctl -S | grep -q "site.local"; then
            a2ensite site.local
        else
            echo "Le site site.local est déjà activé."
        fi
    fi

    # Ajout de l'entrée site.local dans /etc/hosts si elle n'existe pas déjà
    if ! grep -q "site.local" /etc/hosts; then
        echo "192.168.0.2 site.local" >> /etc/hosts
        echo "Entrée 'site.local' ajoutée dans /etc/hosts."
    else
        echo "L'entrée 'site.local' existe déjà dans /etc/hosts."
    fi

    # Définition globale du ServerName dans Apache, si non déjà défini
    if ! grep -q "^ServerName" "$config_dir/httpd.conf"; then
        echo "ServerName site.local" >> "$config_dir/httpd.conf"
        echo "Directive 'ServerName site.local' ajoutée dans $config_dir/httpd.conf."
    else
        echo "La directive ServerName est déjà définie dans $config_dir/httpd.conf."
    fi

    # Redémarrer le service Web pour appliquer les modifications
    if systemctl restart "$service_name"; then
        echo "Serveur web configuré et service redémarré avec succès."
    else
        echo "Erreur lors du redémarrage du service Web."
    fi
}

config_mail() {
    echo "Configuration du serveur de mail..."

    # Détection du service Mail installé
    case "$DETECTED_MAIL" in
        "postfix")
            postfix_conf_dir="/etc/postfix"
            service_postfix="postfix"
            ;;
        "mail_server")
            postfix_conf_dir="/etc/postfix"
            service_postfix="postfix"
            ;;
        *)
            echo "Service de mail non reconnu : $DETECTED_MAIL"
            return 1
            ;;
    esac

    # Détection du service de messagerie Dovecot
    case "$DETECTED_MESSAGING" in
        "dovecot")
            dovecot_conf_dir="/etc/dovecot"
            service_dovecot="dovecot"
            ;;
        "dovecot_core")
            dovecot_conf_dir="/etc/dovecot"
            service_dovecot="dovecot"
            ;;
        *)
            echo "Service de messagerie non reconnu : $DETECTED_MESSAGING"
            return 1
            ;;
    esac

    # Sauvegarder les fichiers de configuration avant modification
    cp "$postfix_conf_dir/main.cf" "$postfix_conf_dir/main.cf.bak"
    cp "$dovecot_conf_dir/dovecot.conf" "$dovecot_conf_dir/dovecot.conf.bak"

    # Configuration de Postfix
    tee "$postfix_conf_dir/main.cf" > /dev/null <<'EOF'
myhostname = site.local
mydomain = site.local
myorigin = $mydomain
mydestination = $myhostname, localhost.$mydomain, localhost
relayhost =
inet_interfaces = all
inet_protocols = ipv4
smtpd_banner = $myhostname ESMTP Postfix
mynetworks = 127.0.0.0/8
mailbox_size_limit = 0
recipient_delimiter = +
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
home_mailbox = Maildir/
setgid_group = mail
compatibility_level = 3.6
EOF

    # Configuration de Dovecot
    tee "$dovecot_conf_dir/dovecot.conf" > /dev/null <<'EOF'
protocols = imap pop3
mail_location = maildir:~/Maildir
userdb {
  driver = passwd
}
passdb {
  driver = pam
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
EOF

    # Désactivation du chroot dans Postfix
    if [ -f "$postfix_conf_dir/master.cf" ]; then
        cp "$postfix_conf_dir/master.cf" "$postfix_conf_dir/master.cf.bak"
        sed -i 's/^\(\S\+\s\+\S\+\s\+\S\+\s\+\S\+\s\+\)y/\1n/' "$postfix_conf_dir/master.cf"
        echo "Chroot désactivé pour les services Postfix dans $postfix_conf_dir/master.cf."
    fi

    # Création d'un lien symbolique pour que Postfix trouve le répertoire attendu
    if [ ! -d /usr/libexec/postfix ]; then
        mkdir -p /usr/libexec
        ln -s /usr/lib/postfix /usr/libexec/postfix
        echo "Lien symbolique /usr/libexec/postfix -> /usr/lib/postfix créé."
    fi

    # Redémarrer les services de Mail
    if systemctl restart "$service_postfix" && systemctl restart "$service_dovecot"; then
        echo "Serveur de mail configuré et services redémarrés avec succès."
    else
        echo -e "${ROUGE}Erreur lors du redémarrage des services de mail.${RESET}"
    fi
}

config_ntp() {

    echo "Configuration du serveur NTP..."

    # Détection du service NTP installé
    case "$DETECTED_NTP" in
        "chronyd")
            ntp_conf_file="/etc/chrony.conf"
            service_name="chronyd"
            ;;
        "ntpd")
            ntp_conf_file="/etc/ntp.conf"
            service_name="ntpd"
            ;;
        "systemd-timesyncd")
            ntp_conf_file="/etc/systemd/timesyncd.conf"
            service_name="systemd-timesyncd"
            ;;
        *)
            echo "Service NTP non reconnu : $DETECTED_NTP"
            return 1
            ;;
    esac

    # Sauvegarde du fichier de configuration s'il existe déjà
    [ -f "$ntp_conf_file" ] && cp "$ntp_conf_file" "$ntp_conf_file.bak"

    # Configuration du fichier de configuration
    if [ "$DETECTED_NTP" == "chronyd" ]; then
        tee "$ntp_conf_file" > /dev/null <<EOF
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst

allow 192.168.0.0/24  #Autorise le réseau local à interroger ce serveur
EOF
    elif [ "$DETECTED_NTP" == "ntpd" ]; then
        tee "$ntp_conf_file" > /dev/null <<EOF
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst

restrict 192.168.0.0 mask 255.255.255.0 nomodify notrap
EOF
    elif [ "$DETECTED_NTP" == "systemd-timesyncd" ]; then
        tee "$ntp_conf_file" > /dev/null <<EOF
[Time]
NTP=0.pool.ntp.org 1.pool.ntp.org
EOF
    fi

    # Vérifier si le service NTP est actif et l'activer si nécessaire
    if systemctl is-active --quiet "$service_name"; then
        echo "Le service NTP ($service_name) est déjà actif. Redémarrage..."
    else
        echo "Le service NTP ($service_name) n'est pas actif. Activation du service..."
        systemctl enable --now "$service_name"
    fi

    # Redémarrer le service NTP
    systemctl restart "$service_name"

    echo "Serveur NTP configuré et service redémarré avec succès."
}

config_nfs() {

    echo "Configuration de la backup avec le serveur tiers..."

    # Détection du service NFS installé
    case "$DETECTED_NFS" in
        "nfs-kernel-server")
            service_name="nfs-kernel-server"
            package_name="nfs-kernel-server"
            ;;
        "nfs-utils")
            service_name="nfs-server"
            package_name="nfs-utils"
            ;;
        "nfs-common")
            service_name="nfs-server"
            package_name="nfs-common"
            ;;
        *)
            echo "Service NFS non reconnu : $DETECTED_NFS"
            return 1
            ;;
    esac

    # Vérifier si le package NFS est installé, sinon l'installer
    if ! command -v mount.nfs &> /dev/null; then
        echo "Le package NFS ($package_name) n'est pas installé. Installation en cours..."
        $DETECTED_PM install -y $package_name
    fi

    # Démarrer le service NFS si nécessaire
    if ! systemctl is-active --quiet "$service_name"; then
        echo "Le service NFS ($service_name) n'est pas actif. Activation du service..."
        systemctl enable --now "$service_name"
    fi

    # Création des répertoires de montage locaux
    for dir in /mnt/nfs/var/log /mnt/nfs/var/www /mnt/nfs/var/srv; do
        [ ! -d "$dir" ] && mkdir -p "$dir"
    done

    # Montage des répertoires NFS
    for dir in /mnt/nfs/var/log /mnt/nfs/var/www /mnt/nfs/var/srv; do
        mount -t nfs 192.168.0.3:/backups "$dir"
    done

    # Configuration de /etc/fstab
    tee -a /etc/fstab > /dev/null <<EOF
192.168.0.3:/backups /mnt/nfs/var/log nfs defaults 0 0
192.168.0.3:/backups /mnt/nfs/var/www nfs defaults 0 0
192.168.0.3:/backups /mnt/nfs/var/srv nfs defaults 0 0
EOF

    # Synchronisation initiale avec rsync
    rsync -av --delete /var/log/ /mnt/nfs/var/log/
    rsync -av --delete /var/www/ /mnt/nfs/var/www/
    rsync -av --delete /var/srv/ /mnt/nfs/var/srv/

    # Création du script de backup
    tee /usr/local/bin/backup.sh > /dev/null <<EOF
#!/bin/bash
rsync -av --delete /var/log/ /mnt/nfs/var/log/
rsync -av --delete /var/www/ /mnt/nfs/var/www/
rsync -av --delete /var/srv/ /mnt/nfs/var/srv/
EOF

    chmod +x /usr/local/bin/backup.sh

    # Configuration de la tâche cron
    if command -v crontab &> /dev/null; then
        (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup.sh") | crontab -
        echo "Tâche cron ajoutée pour les backups quotidiens."
    else
        echo "Crontab n'est pas installé ou non disponible sur ce système."
    fi

    echo "Serveurs NFS configurés avec succès."
}
#----------Fin de déclaration des fonctions de config
#----------------------------------------------------


#-----------------------------------------------------
#----------Déclaration des fonctions de config de test

test_all_all() {
    test_ip
    test_services
    test_firewall
    test_ssh
    test_dns
    test_web
    test_mail
    test_ntp
    test_nfs
}

test_ip() {
    echo -e "${BLEU}Vérification de la configuration IP du client...${RESET}"

    # Déclaration des listes locales pour éviter les conflits globaux
    local errors_ip=()
    local success_ip=()

    # Récupération de l'adresse IP actuelle configurée sur les interfaces réseau (ignorer 127.0.0.1)
    current_ip=$(ip -o -4 addr show | grep -v "127.0.0.1" | awk '{print $4}' | cut -d'/' -f1)

    if [ -n "$current_ip" ]; then
        # Définir automatiquement SERVER_IP
        SERVER_IP="$current_ip"
        success_ip+=("L'adresse IP actuelle configurée sur l'interface réseau est : $SERVER_IP")
    else
        errors_ip+=("Impossible de détecter l'adresse IP actuelle sur les interfaces réseau.")
    fi

    # Calcul automatique de BACKUP_IP (adresse suivante)
    if [ -n "$SERVER_IP" ]; then
        ip_base=$(echo "$SERVER_IP" | cut -d'.' -f1-3)
        last_octet=$(echo "$SERVER_IP" | cut -d'.' -f4)
        
        if (( last_octet < 255 )); then
            BACKUP_IP="${ip_base}.$((last_octet + 1))"
            success_ip+=("L'adresse IP de backup déterminée automatiquement serait : $BACKUP_IP")
        else
            errors_ip+=("Impossible de définir l'adresse de backup, le dernier octet est déjà à 255.")
        fi
    fi

    # Vérification de la présence de l'adresse IP dans /etc/hosts
    if grep -q "$SERVER_IP" /etc/hosts; then
        success_ip+=("L'adresse IP $SERVER_IP est correctement configurée dans /etc/hosts.")
    else
        errors_ip+=("L'adresse IP $SERVER_IP n'est pas présente dans /etc/hosts.")
    fi

    if grep -q "$BACKUP_IP" /etc/hosts; then
        success_ip+=("L'adresse IP du serveur de backup $BACKUP_IP est correctement configurée dans /etc/hosts.")
    else
        errors_ip+=("L'adresse IP du serveur de backup $BACKUP_IP n'est pas présente dans /etc/hosts.")
    fi

    # Affichage des réussites
    for result in "${success_ip[@]}"; do
        echo -e "${VERT}$result${RESET}"
    done

    # Affichage des erreurs
    for result in "${errors_ip[@]}"; do
        echo -e "${ROUGE}$result${RESET}"
    done

    echo -e "${BLEU}Test de vérification IP terminé.${RESET}"
}

test_services() {

    echo -e "${BLEU}Début du test sur les services...${RESET}"

    # Déclaration des listes comme locales pour éviter les conflits globaux
    local errors_serv=()
    local success_serv=()
    local pkg_command=""
    local services=()

    # Détection de la commande à utiliser pour vérifier les paquets installés
    case "$DETECTED_PM" in
        "apt"|"apt-get"|"dpkg")
            pkg_command="dpkg -l"
            ;;
        "dnf"|"yum"|"rpm")
            pkg_command="rpm -q"
            ;;
        "pacman")
            pkg_command="pacman -Q"
            ;;
        "zypper")
            pkg_command="rpm -q"
            ;;
        *)
            echo -e "${ROUGE}Gestionnaire de paquets non reconnu : $DETECTED_PM${RESET}"
            return 1
            ;;
    esac

    # Vérification de l'installation des paquets
    for pkg in "${packages[@]}"; do
        if $pkg_command "$pkg" &>/dev/null; then
            success_serv+=("Paquet installé : $pkg")
        else
            errors_serv+=("Paquet non installé : $pkg")
        fi
    done

    # Détection dynamique des services en fonction de leur type
    case "$DETECTED_WEB" in
        "apache2") services+=("apache2") ;;
        "httpd") services+=("httpd") ;;
        "httpd24") services+=("httpd24") ;;
    esac

    case "$DETECTED_MAIL" in
        "postfix") services+=("postfix") ;;
        "mail_server") services+=("postfix") ;;
    esac

    case "$DETECTED_MESSAGING" in
        "dovecot") services+=("dovecot") ;;
        "dovecot_core") services+=("dovecot") ;;
    esac

    case "$DETECTED_NTP" in
        "chronyd") services+=("chronyd") ;;
        "ntpd") services+=("ntpd") ;;
        "systemd-timesyncd") services+=("systemd-timesyncd") ;;
    esac

    case "$DETECTED_NFS" in
        "nfs-kernel-server") services+=("nfs-server") ;;
        "nfs-utils") services+=("nfs-server") ;;
        "nfs-common") services+=("nfs-server") ;;
    esac

    case "$DETECTED_FW" in
        "firewalld") services+=("firewalld") ;;
        "ufw") services+=("ufw") ;;
        "iptables") services+=("iptables") ;;
        "nftables") services+=("nftables") ;;
        "pf") services+=("pf") ;;
    esac

    case "$DETECTED_SSH" in
        "openssh_server"|"openssh") services+=("sshd") ;;
        "dropbear") services+=("dropbear") ;;
        "tinyssh") services+=("tinysshd") ;;
    esac

    # Vérification de l'activation des services
    for svc in "${services[@]}"; do
        if systemctl is-active --quiet "$svc"; then
            success_serv+=("Service actif : $svc")
        else
            errors_serv+=("Service non actif : $svc")
        fi
    done

    # Affichage des réussites en vert
    for success in "${success_serv[@]}"; do
        echo -e "${VERT}${success}${RESET}"
    done

    # Affichage des erreurs en rouge
    for error in "${errors_serv[@]}"; do
        echo -e "${ROUGE}${error}${RESET}"
    done

    echo -e "${BLEU}Test sur les services terminé.${RESET}"
}

test_firewall() {
    echo -e "${BLEU}Début du test sur le firewall...${RESET}"

    # Déclaration des listes locales pour éviter les conflits globaux
    local errors_firewall=()
    local success_firewall=()
    local firewall_command=""

    # Détection du nom du firewall en fonction de $DETECTED_FW
    case "$DETECTED_FW" in
        "firewalld")
            firewall_command="firewall-cmd --list-ports"
            ;;
        "ufw")
            firewall_command="ufw status"
            ;;
        "iptables")
            firewall_command="iptables -L -n -v"
            ;;
        "nftables")
            firewall_command="nft list ruleset"
            ;;
        "pf")
            firewall_command="pfctl -sr"
            ;;
        *)
            errors_firewall+=("Service Firewall non reconnu : $DETECTED_FW")
            echo -e "${ROUGE}Service Firewall non reconnu : $DETECTED_FW${RESET}"
            return 1
            ;;
    esac

    # Vérification des ports ouverts (en fonction du firewall détecté)
    for port in "${expected_ports[@]}"; do
        case "$DETECTED_FW" in
            "firewalld")
                if $firewall_command | grep -q "$port"; then
                    success_firewall+=("Port $port est ouvert.")
                else
                    errors_firewall+=("Port $port n'est pas ouvert.")
                fi
                ;;
            "ufw")
                if $firewall_command | grep -q "ALLOW.*$port"; then
                    success_firewall+=("Port $port est ouvert.")
                else
                    errors_firewall+=("Port $port n'est pas ouvert.")
                fi
                ;;
            "iptables")
                if $firewall_command | grep -q "$port"; then
                    success_firewall+=("Port $port est ouvert.")
                else
                    errors_firewall+=("Port $port n'est pas ouvert.")
                fi
                ;;
            "nftables")
                if $firewall_command | grep -q "dport $port"; then
                    success_firewall+=("Port $port est ouvert.")
                else
                    errors_firewall+=("Port $port n'est pas ouvert.")
                fi
                ;;
            "pf")
                if $firewall_command | grep -q "port $port"; then
                    success_firewall+=("Port $port est ouvert.")
                else
                    errors_firewall+=("Port $port n'est pas ouvert.")
                fi
                ;;
        esac
    done

    # Affichage des réussites
    for success in "${success_firewall[@]}"; do
        echo -e "${VERT}$success${RESET}"
    done

    # Affichage des erreurs
    for error in "${errors_firewall[@]}"; do
        echo -e "${ROUGE}$error${RESET}"
    done

    echo -e "${BLEU}Test du firewall terminé.${RESET}"
}

test_ssh() {
    echo -e "${BLEU}Début du test SSH...${RESET}"
    
    # Déclaration des listes locales pour éviter les conflits globaux
    local errors_ssh=()
    local success_ssh=()
    local ssh_service_name=""

    # Détection du nom du service SSH en fonction de $DETECTED_SSH
    case "$DETECTED_SSH" in
        "openssh_server"|"openssh") ssh_service_name="sshd" ;;
        "dropbear") ssh_service_name="dropbear" ;;
        "tinyssh") ssh_service_name="tinysshd" ;;
        *)
            errors_ssh+=("Service SSH non reconnu : $DETECTED_SSH")
            echo -e "${ROUGE}Service SSH non reconnu : $DETECTED_SSH${RESET}"
            return 1
            ;;
    esac

    # Vérification que le port 22 est fermé
    if firewall-cmd --list-ports | grep -q "22/tcp"; then
        errors_ssh+=("Port 22 est encore ouvert.")
    else
        success_ssh+=("Port 22 est fermé.")
    fi

    # Vérification que le port 2025 est ouvert
    if firewall-cmd --list-ports | grep -q "2025/tcp"; then
        success_ssh+=("Port 2025 est ouvert.")
    else
        errors_ssh+=("Port 2025 n'est pas ouvert.")
    fi

    # Vérification que SSH écoute sur le port 2025
    if ss -tuln | grep -q ":2025"; then
        success_ssh+=("SSH écoute sur le port 2025.")
    else
        errors_ssh+=("SSH n'écoute pas sur le port 2025.")
    fi

    # Vérification que le service SSH est actif
    if systemctl is-active --quiet "$ssh_service_name"; then
        success_ssh+=("Service SSH ($ssh_service_name) est actif.")
    else
        errors_ssh+=("Service SSH ($ssh_service_name) n'est pas actif.")
    fi

    # Affichage des réussites
    for result in "${success_ssh[@]}"; do
        echo -e "${VERT}$result${RESET}"
    done

    # Affichage des erreurs
    for result in "${errors_ssh[@]}"; do
        echo -e "${ROUGE}$result${RESET}"
    done

    echo -e "${BLEU}Test SSH terminé.${RESET}"
}


test_dns() {

    echo -e "${BLEU}Début du test DNS...${RESET}"

    # Déclaration des listes locales pour éviter les conflits globaux
    local errors_dns=()
    local success_dns=()
    local service_name=""

    # Détection du nom du service DNS en fonction de la valeur de $DETECTED_DNS
    case "$DETECTED_DNS" in
        "bind9")
            service_name="bind9"
            ;;
        "bind")
            service_name="named"
            ;;
        "bind_utils")
            service_name="named"
            ;;
        "unbound")
            service_name="unbound"
            ;;
        *)
            errors_dns+=("Service DNS non reconnu : $DETECTED_DNS")
            echo -e "${ROUGE}Service DNS non reconnu : $DETECTED_DNS${RESET}"
            return 1
            ;;
    esac

    # Vérifier l'état du service DNS détecté
    if ! systemctl is-active --quiet "$service_name"; then
        errors_dns+=("Le service DNS ($service_name) n'est actuellement pas actif.")
    else
        success_dns+=("Le service DNS ($service_name) est actif.")
    fi

    # Vérifier la résolution d'un domaine via le DNS local
    dns_result=$(dig @127.0.0.1 google.com +short)
    if [[ -z "$dns_result" ]]; then
        errors_dns+=("La résolution de google.com via le serveur DNS local a échoué.")
    elif ! echo "$dns_result" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"; then
        errors_dns+=("La résolution de google.com ne renvoie pas d'adresse IPv4 valide.")
    else
        success_dns+=("La résolution de google.com via le serveur DNS local fonctionne correctement.")
    fi

    # Affichage des réussites
    for result in "${success_dns[@]}"; do
        echo -e "${VERT}$result${RESET}"
    done

    # Affichage des erreurs
    for result in "${errors_dns[@]}"; do
        echo -e "${ROUGE}$result${RESET}"
    done

    echo -e "${BLEU}Test DNS terminé.${RESET}"
}

test_web() {
    echo -e "${BLEU}Début du test Web...${RESET}"

    # Déclaration des listes locales pour éviter les conflits globaux
    local errors_web=()
    local success_web=()
    local web_service_name=""
    local web_port=80

    # Détection dynamique du serveur web configuré
    case "$DETECTED_WEB" in
        "apache2")
            web_service_name="apache2"
            ;;
        "httpd")
            web_service_name="httpd"
            ;;
        "httpd24")
            web_service_name="httpd24"
            ;;
        "nginx")
            web_service_name="nginx"
            web_port=80
            ;;
        *)
            errors_web+=("Service Web non reconnu : $DETECTED_WEB")
            echo -e "${ROUGE}Service Web non reconnu : $DETECTED_WEB${RESET}"
            return 1
            ;;
    esac

    # Vérification de l'activation du service Web détecté
    if systemctl is-active --quiet "$web_service_name"; then
        success_web+=("Le service Web ($web_service_name) est actif.")
    else
        errors_web+=("Le service Web ($web_service_name) n'est pas actif.")
    fi

    # Vérification de l'ouverture du port
    if ss -tln | grep -q ":$web_port "; then
        success_web+=("Le port $web_port est ouvert.")
    else
        errors_web+=("Le port $web_port semble être fermé.")
    fi

    # Vérification de l'accessibilité du serveur web avec curl
    if curl -s --head "http://127.0.0.1:$web_port" -H "Host: site.local" | grep -q "200 OK"; then
        success_web+=("Le serveur web répond correctement avec un code HTTP 200.")
    else
        errors_web+=("Le serveur web ne répond pas correctement (pas de réponse HTTP 200).")
    fi

    # Affichage des résultats du test web avec les couleurs
    for result in "${success_web[@]}"; do
        echo -e "${VERT}$result${RESET}"
    done

    for result in "${errors_web[@]}"; do
        echo -e "${ROUGE}$result${RESET}"
    done

    echo -e "${BLEU}Test Web terminé.${RESET}"
}

test_mail() {
    echo -e "${BLEU}Début du test Mail...${RESET}"

    # Déclaration des listes locales pour éviter les conflits globaux
    local errors_mail=()
    local success_mail=()
    local mail_services=()

    # Détection dynamique des services de messagerie configurés
    case "$DETECTED_MAIL" in
        "postfix"|"mail_server") mail_services+=("postfix") ;;
    esac

    case "$DETECTED_MESSAGING" in
        "dovecot"|"dovecot_core") mail_services+=("dovecot") ;;
    esac

    # Vérification de l'activation des services de messagerie détectés
    for svc in "${mail_services[@]}"; do
        if systemctl is-active --quiet "$svc"; then
            success_mail+=("Le service $svc est actif.")
        else
            errors_mail+=("Le service $svc n'est pas actif.")
        fi
    done

    # Vérification de l'ouverture des ports mail standards
    ports=("25" "465" "587" "143" "993")
    for port in "${ports[@]}"; do
        if ss -tln | grep -q ":$port"; then
            success_mail+=("Le port $port (mail) est ouvert.")
        else
            errors_mail+=("Le port $port (mail) n'est pas ouvert.")
        fi
    done

    # Test d'envoi de mail local - vérification que sendmail est disponible
    if command -v sendmail &>/dev/null; then
        echo "Test mail" | sendmail root
        sleep 2  # Attente pour que le mail soit traité

        # Vérification que le mail a bien été déposé dans le Maildir de root
        if [ -d /root/Maildir/new ] && [ "$(ls -A /root/Maildir/new)" ]; then
            success_mail+=("L'envoi de mail local fonctionne.")
        else
            errors_mail+=("L'envoi de mail local ne semble pas fonctionner correctement.")
        fi
    else
        errors_mail+=("La commande sendmail n'est pas disponible.")
    fi

    # Affichage des réussites en vert
    for result in "${success_mail[@]}"; do
        echo -e "${VERT}$result${RESET}"
    done

    # Affichage des erreurs en rouge
    for result in "${errors_mail[@]}"; do
        echo -e "${ROUGE}$result${RESET}"
    done

    echo -e "${BLEU}Test Mail terminé.${RESET}"
}

test_ntp() {
    echo -e "${BLEU}Début du test NTP...${RESET}"

    # Déclaration des listes locales pour éviter les conflits globaux
    local errors_ntp=()
    local success_ntp=()
    local ntp_service_name=""

    # Détection dynamique du service NTP configuré
    case "$DETECTED_NTP" in
        "chronyd")
            ntp_service_name="chronyd"
            ;;
        "ntpd")
            ntp_service_name="ntpd"
            ;;
        "systemd-timesyncd")
            ntp_service_name="systemd-timesyncd"
            ;;
        *)
            errors_ntp+=("Service NTP non reconnu : $DETECTED_NTP")
            echo -e "${ROUGE}Service NTP non reconnu : $DETECTED_NTP${RESET}"
            return 1
            ;;
    esac

    # Vérification de l'activation du service NTP détecté
    if systemctl is-active --quiet "$ntp_service_name"; then
        success_ntp+=("Le service $ntp_service_name (NTP) est actif.")
    else
        errors_ntp+=("Le service $ntp_service_name (NTP) ne semble pas être actif.")
    fi

    # Vérification de l'ouverture du port NTP (UDP 123)
    if ss -uln | grep -q ":123"; then
        success_ntp+=("Le port 123/UDP (NTP) est ouvert.")
    else
        errors_ntp+=("Il semblerait que le port 123/UDP (NTP) ne soit pas ouvert.")
    fi

    # Vérification de la synchronisation du temps
    if [ "$ntp_service_name" = "chronyd" ]; then
        if chronyc tracking | grep -q "Reference ID"; then
            success_ntp+=("Le serveur NTP ($ntp_service_name) est synchronisé avec une source de temps.")
        else
            errors_ntp+=("Le serveur NTP ($ntp_service_name) ne semble pas synchronisé avec une source de temps.")
        fi
    elif [ "$ntp_service_name" = "ntpd" ]; then
        if ntpq -p 127.0.0.1 &>/dev/null; then
            success_ntp+=("Le serveur NTP ($ntp_service_name) est synchronisé avec une source de temps.")
        else
            errors_ntp+=("Le serveur NTP ($ntp_service_name) ne semble pas synchronisé avec une source de temps.")
        fi
    elif [ "$ntp_service_name" = "systemd-timesyncd" ]; then
        if timedatectl status | grep -q "NTP synchronized: yes"; then
            success_ntp+=("Le serveur NTP ($ntp_service_name) est synchronisé avec une source de temps.")
        else
            errors_ntp+=("Le serveur NTP ($ntp_service_name) ne semble pas synchronisé avec une source de temps.")
        fi
    fi

    # Affichage des réussites en vert
    for result in "${success_ntp[@]}"; do
        echo -e "${VERT}$result${RESET}"
    done

    # Affichage des erreurs en rouge
    for result in "${errors_ntp[@]}"; do
        echo -e "${ROUGE}$result${RESET}"
    done

    echo -e "${BLEU}Test NTP terminé.${RESET}"
}

test_nfs() {
    echo -e "${BLEU}Début du test NFS...${RESET}"

    # Déclaration des listes locales pour éviter les conflits globaux
    local errors_backup=()
    local success_backup=()
    local nfs_service_name=""
    local nfs_ports=("2049" "111")  # Ports courants utilisés par NFS

    # Détection dynamique du service NFS configuré
    case "$DETECTED_NFS" in
        "nfs-kernel-server")
            nfs_service_name="nfs-server"
            ;;
        "nfs-utils")
            nfs_service_name="nfs-server"
            ;;
        "nfs-common")
            nfs_service_name="nfs-server"
            ;;
        *)
            errors_backup+=("Service NFS non reconnu : $DETECTED_NFS")
            echo -e "${ROUGE}Service NFS non reconnu : $DETECTED_NFS${RESET}"
            return 1
            ;;
    esac

    # Vérification de l'activation du service NFS détecté
    if systemctl is-active --quiet "$nfs_service_name"; then
        success_backup+=("Le service NFS ($nfs_service_name) est actif.")
    else
        errors_backup+=("Le service NFS ($nfs_service_name) n'est pas actif.")
    fi

    # Vérification de l'ouverture des ports NFS
    for port in "${nfs_ports[@]}"; do
        if ss -tuln | grep -q ":$port"; then
            success_backup+=("Le port $port (NFS) est ouvert.")
        else
            errors_backup+=("Le port $port (NFS) n'est pas ouvert.")
        fi
    done

    # Test de sauvegarde et restauration
    SOURCE="/var/www"
    BACKUP_DIR="/tmp/backup_test"
    BACKUP_FILE="/tmp/backup_www.tar.gz"
    RESTORE_DIR="/tmp/www_restored"

    # Vérifier si le dossier source existe
    if [ ! -d "$SOURCE" ]; then
        errors_backup+=("Le dossier source $SOURCE n'existe pas.")
    else
        success_backup+=("Le dossier source $SOURCE existe.")
    fi

    # Si le dossier source existe, on continue
    if [ -d "$SOURCE" ]; then
        # Création d'une copie temporaire pour le test
        cp -a "$SOURCE" "$BACKUP_DIR"

        if [ -d "$BACKUP_DIR" ]; then
            success_backup+=("La copie temporaire a été créée avec succès.")
        else
            errors_backup+=("Échec de la copie temporaire.")
        fi

        # Sauvegarde de la copie
        tar -czf "$BACKUP_FILE" -C "$BACKUP_DIR" .

        if [ -f "$BACKUP_FILE" ]; then
            success_backup+=("La sauvegarde a été créée avec succès.")
        else
            errors_backup+=("Échec de la création de la sauvegarde.")
        fi

        # Suppression de la copie temporaire
        rm -rf "$BACKUP_DIR"
        
        if [ ! -d "$BACKUP_DIR" ]; then
            success_backup+=("La copie temporaire a été supprimée avec succès.")
        else
            errors_backup+=("Échec de la suppression de la copie temporaire.")
        fi

        # Restauration de la sauvegarde
        mkdir -p "$RESTORE_DIR"
        tar -xzf "$BACKUP_FILE" -C "$RESTORE_DIR"

        if [ "$(ls -A "$RESTORE_DIR")" ]; then
            success_backup+=("La restauration des fichiers a réussi.")
        else
            errors_backup+=("Échec de la restauration des fichiers.")
        fi
    fi

    # Affichage des réussites en vert
    for result in "${success_backup[@]}"; do
        echo -e "${VERT}$result${RESET}"
    done

    # Affichage des erreurs en rouge
    for result in "${errors_backup[@]}"; do
        echo -e "${ROUGE}$result${RESET}"
    done

    echo -e "${BLEU}Test NFS terminé.${RESET}"
}




#----------Fin de déclaration des fonctions de test
#----------------------------------------------------


# Liste des distributions disponibles (ordre important)
distros=(
    "Ubuntu"
    "Debian"
    "Fedora"
    "CentOS"
    "Arch Linux"
    "Linux Mint"
    "openSUSE"
    "RHEL (Red Hat Enterprise Linux)"
    "Manjaro"
    "Zorin OS"
    "Pop!_OS"
    "Kali Linux"
    "MX Linux"
    "AlmaLinux"
    "Rocky Linux"
    "Mageia"
    "FreeBSD"
    "Gentoo"
    "NixOS"
    "Void Linux"
    "GhostBSD"
    "TrueOS"
    "Artix Linux"
    "Alpine Linux"
    "OpenBSD"
)

# Liste des package managers par index
package_managers=(
    "apt"        # 0
    "dnf"        # 1
    "pacman"     # 2
    "xbps"       # 3
    "nix"        # 4
    "apk"        # 5
    "zypper"     # 6
    "portage"    # 7
    "pkg"        # 8
)

# Liste des firewalls par index
firewalls=(
    "firewalld"  # 0
    "ufw"        # 1
    "iptables"   # 2
    "pf"         # 3
    "nftables"   # 4
)

# Liste des serveurs web par index
web_servers=(
    "apache2"   # 0
    "httpd"     # 1
    "apache"    # 2
    "httpd24"   # 3
)

# Liste des serveurs DNS par index
dns_servers=(
    "bind9"       # 0
    "bind"        # 1
    "bind_utils"  # 2
)

# Liste des serveurs SSH par index
ssh_servers=(
    "openssh_server"  # 0
    "openssh"         # 1
)

# Liste des serveurs Mail par index
mail_servers=(
    "postfix"      # 0
    "mail_server"  # 1
)

# Liste des serveurs de messagerie par index
messaging_servers=(
    "dovecot"       # 0
    "dovecot_core"  # 1
)

# Liste des serveurs NFS par index
nfs_servers=(
    "nfs_kernel_server"  # 0
    "nfs_utils"          # 1
    "nfs_common"         # 2
)

# Liste des outils de monitoring par index
monitoring_tools=(
    "btop"  # 0
    "htop"  # 1
)

# Association des distros à leur package manager par index
distro_to_pm_index=(
    0 0 1 1 2 0 6 1 2 0 0 0 0 1 1 1 8 7 4 3 8 8 2 5 8
)

# Association des distros à leur firewall par index
distro_to_fw_index=(
    1 2 0 0 2 1 2 0 2 1 1 1 1 0 0 0 2 2 2 2 3 3 2 2 3
)

# Association des distros à leur serveur web par index
ddistro_to_ws_index=(
    0 0 0 0 1 0 0 0 1 0 0 0 0 0 0 0 0 0 0 1 0 0 1 2 3
)

distro_to_dns_index=(
    0 0 1 1 1 0 1 1 1 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1
)

distro_to_ssh_index=(
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0
)

distro_to_mail_index=(
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0
)

distro_to_msg_index=(
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0
)

distro_to_nfs_index=(
    0 2 0 0 0 2 0 0 0 2 2 2 2 0 0 0 0 0 0 0 0 0 0 1 0
)

distro_to_monitor_index=(
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 1 1 0 0 0
)

# Fonction d'affichage d'un élément via son index
get_element_by_index() {
    local array=("${!1}")
    local index=$2
    echo "${array[$index]}"
}


# Affichage du menu
while true; do
    echo -e "\nBienvenue dans ce setup de serveur! Veuillez choisir une option :\n"

    for i in "${!distros[@]}"; do
        echo "    [$((i+1))] ${distros[$i]}"
    done

    read -rp "Entrez le numéro de votre distribution : " distro_choice

    if (( distro_choice >= 1 && distro_choice <= ${#distros[@]} )); then
        # On soustrait 1 parce que les tableaux Bash commencent à 0
        distro_index=$((distro_choice - 1))
        var_distro="${distros[$distro_index]}"
        
        # Récupération du package manager correspondant
        pm_index="${distro_to_pm_index[$distro_index]}"
        DETECTED_PM=$(get_element_by_index "package_managers[@]" "$pm_index")
        
        # Récupération du firewall correspondant
        fw_index="${distro_to_fw_index[$distro_index]}"
        DETECTED_FW=$(get_element_by_index "firewalls[@]" "$fw_index")

        # Récupération du serveur web correspondant
        ws_index="${distro_to_ws_index[$distro_index]}"
        DETECTED_WS=$(get_element_by_index "web_servers[@]" "$ws_index")

        # Récupération du serveur DNS correspondant
        dns_index="${distro_to_dns_index[$distro_index]}"
        DETECTED_DNS=$(get_element_by_index "dns_servers[@]" "$dns_index")

        # Récupération du serveur SSH correspondant
        ssh_index="${distro_to_ssh_index[$distro_index]}"
        DETECTED_SSH=$(get_element_by_index "ssh_servers[@]" "$ssh_index")

        # Récupération du serveur Mail correspondant
        mail_index="${distro_to_mail_index[$distro_index]}"
        DETECTED_MAIL=$(get_element_by_index "mail_servers[@]" "$mail_index")

        # Récupération du serveur de messagerie correspondant
        msg_index="${distro_to_msg_index[$distro_index]}"
        DETECTED_MSG=$(get_element_by_index "messaging_servers[@]" "$msg_index")

        # Récupération du serveur NFS correspondant
        nfs_index="${distro_to_nfs_index[$distro_index]}"
        DETECTED_NFS=$(get_element_by_index "nfs_servers[@]" "$nfs_index")

        # Récupération de l'outil de monitoring correspondant
        monitor_index="${distro_to_monitor_index[$distro_index]}"
        DETECTED_MONITOR=$(get_element_by_index "monitoring_tools[@]" "$monitor_index")

        echo -e "\nVous avez sélectionné : $var_distro"
        
        break
    else
        echo -e "\nChoix invalide. Veuillez réessayer.\n"
    fi
done

# Test d'affichage des variables stockées
echo -e "\n==> Variables stockées pour utilisation future :"
echo -e "   Gestionnaire de paquets détecté : ${GRAS}$DETECTED_PM${RESET}"
echo -e "   Pare-feu détecté : ${GRAS}$DETECTED_FW${RESET}"
echo -e "   Serveur Web détecté : ${GRAS}$DETECTED_WS${RESET}"
echo -e "   Serveur DNS détecté : ${GRAS}$DETECTED_DNS${RESET}"
echo -e "   Serveur SSH détecté : ${GRAS}$DETECTED_SSH${RESET}"
echo -e "   Serveur Mail détecté : ${GRAS}$DETECTED_MAIL${RESET}"
echo -e "   Serveur de messagerie détecté : ${GRAS}$DETECTED_MSG${RESET}"
echo -e "   Serveur NFS détecté : ${GRAS}$DETECTED_NFS${RESET}"
echo -e "   Outil de monitoring détecté : ${GRAS}$DETECTED_MONITOR${RESET}"

done

# Début de la boucle principale
while true; do

    echo -e "\nVeuillez à présent choisir une option : \n\n[1] : Configuration\n[2] : Test\n"
    echo -e "\n([1] est sélectionné par défaut)"
    #Choix entre la partie Configuration et la partie Test
    read -p "Veuillez choisir un nombre : " main_choice
    main_choice="${main_choice:-1}"


    #Début de la structure conditionnelle principale
    if [ "$main_choice" == "1" ]; then
        echo -e "\nVous avez sélectionné la partie config. Lancement du protocole de setup...\n"

        echo -e "-> Protocole de setup-config lancé avec succès.\n"
        
        echo -e "Options de configuration :
        [1] Tout
        [2] Services
        [3] Pare-feu
        [4] SSH
        [5] DNS
        [6] Web
        [7] Mail
        [8] NTP
        [9] NFS\n"

        read -p "Veuillez entrer le nombre de votre choix ([1] est sélectionné par défaut) : " config_choice
        config_choice="${config_choice:-1}"

        # Début de la boucle pour la partie Configuration
        while true; do

            # Début de la config globale
            if [ "$config_choice" == "1" ] ; then
                config_all
                break

            elif [ "$config_choice" == "2" ] ; then
                config_services
                break

            elif [ "$config_choice" == "3" ] ; then
                config_firewall
                break

            elif [ "$config_choice" == "4" ] ; then
                config_ssh
                break

            elif [ "$config_choice" == "5" ] ; then
                config_dns
                break

            elif [ "$config_choice" == "6" ] ; then
                config_web
                break

            elif [ "$config_choice" == "7" ] ; then
                config_mail
                break

            elif [ "$config_choice" == "8" ] ; then
                config_ntp
                break

            elif [ "$config_choice" == "9" ] ; then
                config_nfs
                break

            # En cas de mauvaise réponse ou hors-sujet
            else
                echo -e "${ROUGE}Veuillez choisir une réponse valide.${RESET}"
            fi
        done

    elif [ "$main_choice" == "2" ] ; then
        echo -e "Vous avez sélectionné la partie test. Il est recommandé d'avoir d'abord été faire un tour du\
        côté config pour avoir matière à tester.\n\n"

        echo -e "-> Protocole de setup-test lancé avec succès.\n"

        echo -e "Options de test :
        [1] Tout
        [2] Services
        [3] Pare-feu
        [4] SSH
        [5] DNS
        [6] Web
        [7] Mail
        [8] NTP
        [9] NFS\n"

        read -p "Veuillez entrer le nombre de votre choix ([1] est sélectionné par défaut) : " test_choice
        test_choice="${test_choice:-1}"

        #Début de la boucle pour la partie Test
        while true; do 

            if [ "$test_choice" == "1" ] ; then

                # Appeler tous les tests
                echo "Début du test complet..."
                
                test_all

                echo -e "${BLEU}Tous les tests sont terminés.${RESET}"

                break
            

            elif [ "$test_choice" == "2" ] ; then

                echo "Début du test des services..."

                test_services

                echo -e "${BLEU}Test des services terminé.${RESET}"

                break
            

            elif [ "$test_choice" == "3" ] ; then
                
                echo "Début du test du firewall..."

                test_firewall

                echo -e "${BLEU}Test du pare-feu terminé.${RESET}"

                break


            elif [ "$test_choice" == "4" ] ; then

                echo "Début du test du SSH..."

                test_ssh

                echo -e "${BLEU}Test du SSH terminé.${RESET}"

                break


            elif [ "$test_choice" == "5" ] ; then

                echo "Début du test du DNS..."

                test_dns

                echo -e "${BLEU}Test du DNS terminé.${RESET}"

                break


            elif [ "$test_choice" == "6" ] ; then

                echo "Début du test des services web."

                test_web

                echo -e "${BLEU}Test des services web terminé.${RESET}"

                break


            elif [ "$test_choice" == "7" ] ; then

                echo "Début du test des mails..."

                test_mail

                echo -e "${BLEU}Test des mails terminé.${RESET}"

                break


            elif [ "$test_choice" == "8" ] ; then

                echo "Début du test NTP..."

                test_ntp

                echo -e "${BLEU}Test NTP terminé.${RESET}"

                break


            elif [ "$test_choice" == "9" ] ; then

                echo "Début du test NFS..."

                test_nfs

                echo -e "${BLEU}Test NFS terminé.${RESET}"

                
            #En cas de mauvaise réponse ou hors-sujet
            else
                echo "${ROUGE}Veuillez choisir une réponse valide.${RESET}"
            fi
        done
        break

    else
        echo -e "Veuillez sélectionner une entrée valable.\n"

    fi
done
