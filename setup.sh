#!/bin/bash

#Déclaration des variables globales
GRAS="\e[1m"
RESET="\e[0m"


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



#----------Fin de déclaration des fonctions de config
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

# Variables globales pour stocker les résultats
DETECTED_PM=""
DETECTED_FW=""
DETECTED_WS=""
DETECTED_DNS=""
DETECTED_SSH=""
DETECTED_MAIL=""
DETECTED_MSG=""
DETECTED_NFS=""
DETECTED_MONITOR=""


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
