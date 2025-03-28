#!/bin/bash

#--------------------------------------------------------
#----------Début de la déclaration des variables globales

# Couleurs pour les résultats des tests
VERT="\e[32m"
ROUGE="\e[31m"
BLEU="\e[34m"
RESET="\e[0m"

# Liste des ports à ouvrir dans le pare-feu
expected_ports=("2025/tcp" "80/tcp" "443/tcp" "53/tcp" "53/udp" "25/tcp" "465/tcp" "587/tcp" "993/tcp" "995/tcp" "123/udp" "2049/tcp" "2049/udp")

# Listes des services et paquets utilisés dans le script
services=("apache2" "named" "sshd" "postfix" "dovecot" "chronyd")
packages=("apache2" "btop" "openssh" "nmap" "nfs-kernel-server" "nfs-client" "bind" "bind-utils" "chrony" "postfix" "dovecot")

#----------Fin de la déclaration des variables globales
#------------------------------------------------------



#---------------------------------------
#----------Début de la boucle principale
while true; do

    echo -e "\nBienvenue dans ce setup de serveur! Veuillez choisir une option : \n\n[1] : Configuration\n[2] : Test\n"
    echo -e "\n([1] est sélectionné par défaut)"


    #Choix entre la partie Configuration et la partie Test
    read -p "Please choose a number : " main_choice
    main_choice="${main_choice:-1}"

    sleep 1


    #Début de la structure conditionnelle principale
    if [ "$main_choice" == "1" ]; then
        echo -e "\nVous avez sélectionné la partie config. Lancement du protocole de setup...\n"
        sleep 2

        echo -e "-> Protocole de setup-config lancé avec succès.\n"
        sleep 1
        
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

        #Début de la boucle pour la partie Configuration
        while true; do

            #Début de la config globale
            if [ "$config_choice" == "1" ] ; then

                #Appeler toutes les config
                echo "Début de la configuration complète..."

                config_all() {
                    config_services
                    config_firewall
                    config_ssh
                    config_dns
                    config_web
                    config_mail
                    config_ntp
                    config_nfs
                }

                echo "Configuration complète terminée."

                break


            elif [ "$config_choice" == "2" ] ; then

                config_services() {
                    echo -e "Configuration du serveur en cours..."
                    sleep 2


                    #-----------------------------------------------
                    #----Début de l'installation des services requis

                    #Liste des paquets à installer
                    #->Déjà déclarée avant le début de la main loop

                    # Installation des paquets
                    for package in "${packages[@]}"; do
                        if ! zypper info "$package" &>/dev/null; then
                            echo -e "Installation de $package..."
                            zypper install -y "$package"
                        else
                            echo -e "$package est déjà installé."
                        fi
                    done

                    #-------Fin de l'installation des services requis
                    #------------------------------------------------


                    #-----------------------------------------------
                    #------------------Démarrage des services requis

                    #Liste des services à démarrer
                    #->Déjà déclarée avant le début de la main loop

                    # Démarrer les services
                    for service in "${services[@]}"; do
                        if ! systemctl is-active --quiet "$service"; then
                            echo -e "Démarrage du service $service..."
                            systemctl enable --now "$service"
                        else
                            echo -e "$service est déjà en cours d'exécution."
                        fi
                    done

                    #-----------------------------------------------
                    #-----------Fin du démarrage des services requis
                }

                break
                

            elif [ "$config_choice" == "3" ] ; then

                config_firewall() {
                    #-----------------------------------------------
                    #----------Début de la configuration du pare-feu

                    #Service SSH
                    firewall-cmd --permanent --remove-port=22/tcp #->On retire le port SSH par défaut

                    #Ouverture des ports pour les autres services
                    echo "Début de la configuration du pare-feu..."

                    # Ouverture des ports spécifiés dans la liste expected_ports
                    for port in "${expected_ports[@]}"; do

                        firewall-cmd --permanent --add-port="$port"

                    done

                    # Recharge de la configuration du pare-feu
                    firewall-cmd --reload

                    echo -e "${BLUE}Configuration du pare-feu terminée.${RESET}"

                    #----------Fin de la configuration du pare-feu
                    #---------------------------------------------
                }

                break


            elif [ "$config_choice" == "4" ] ; then

                config_ssh() {
                    #------------------------------------------
                    #----------Début de la configuration du SSH


                    # Sauvegarder le fichier de configuration avant modification
                    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

                    #Changement du port SSH
                    sed -i 's/^Port 22/Port 2025/' /etc/ssh/sshd_config

                    # Redémarrer le service SSH
                    if systemctl restart sshd; then

                        echo "Service SSH redémarré avec succès."
                        
                    else

                        echo "Erreur lors du redémarrage du service SSH."

                    fi

                    echo "Service SSH configuré. Le port dédié est 2025."

                    #----------Fin de la configuation du SSH
                    #---------------------------------------
                }

                break


            elif [ "$config_choice" == "5" ] ; then

                config_dns() {
                    #------------------------------------------
                    #----------Début de la configuartion du DNS
                    echo "Configuration du serveur DNS..."

                    # Sauvegarder les fichiers de config avant toute modification
                    [ -f /etc/named.conf ] && cp /etc/named.conf /etc/named.conf.bak
                    [ -f /var/lib/named/site.local.zone ] && cp /var/lib/named/site.local.zone /var/lib/named/site.local.zone.bak
                    [ -f /var/lib/named/0.168.192.in-addr.arpa.zone ] && cp /var/lib/named/0.168.192.in-addr.arpa.zone /var/lib/named/0.168.192.in-addr.arpa.zone.bak

                    # Configurer named.conf
                    tee /etc/named.conf > /dev/null <<EOF
                    zone "monsite.local" IN {
                        type master;
                        file "/var/lib/named/monsite.local.zone";
                    };

                    zone "0.168.192.in-addr.arpa" IN {
                        type master;
                        file "/var/lib/named/0.168.192.in-addr.arpa.zone";
                    };

                    forwarders {
                        1.1.1.1;
                        8.8.8.8;
                    };
EOF
                    # Configurer la zone pour le domaine principal
                    tee /var/lib/named/site.local.zone > /dev/null <<EOF
                    \$TTL 86400
                    @   IN  SOA site.local. admin.site.local. (
                            2025022801 ; Serial
                            3600       ; Refresh
                            1800       ; Retry
                            604800     ; Expire
                            86400 )    ; Minimum TTL

                        IN  NS  ns.site.local.
                    ns  IN  A   192.168.0.2  ; IP du serveur DNS
                    @   IN  A   192.168.0.2  ; IP du serveur Web
                    www IN  A   192.168.0.2  ; Alias pour le serveur Web
EOF
                    # Configurer la zone pour la reverse DNS
                    tee /var/lib/named/0.168.192.in-addr.arpa.zone > /dev/null <<EOF
                    \$TTL 86400
                    @   IN  SOA monsite.local. admin.monsite.local. (
                            2025022801 ; Serial
                            3600       ; Refresh
                            1800       ; Retry
                            604800     ; Expire
                            86400 )    ; Minimum TTL

                        IN  NS  ns.site.local.
                    2   IN  PTR site.local.
EOF
                    # Redémarrer le service DNS
                    if systemctl restart named.service; then
                        echo "Serveur DNS configuré et service redémarré avec succès."
                    else
                        echo "Erreur lors du redémarrage du service DNS."
                    fi

                    #----------Fin de la configuration du DNS
                    #----------------------------------------
                }

                break


                elif [ "$config_choice" == "6" ] ; then

                    config_web() {
                        #--------------------------------------------------
                        #----------Début de la configuration du service web

                        echo "Configuration du serveur web..."

                        # Création du fichier de configuration de VirtualHost
                        tee /etc/apache2/vhosts.d/site.local.conf > /dev/null <<EOF
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

                        # Activation du site, en vérifiant s'il n'est pas déjà activé

                        if ! apache2ctl -S | grep -q "site.local"; then

                            a2ensite site.local

                        else

                            echo "Le site site .local est déjà activé."
                            
                        fi

                        # Redémarrer Apache pour appliquer les modifications
                        systemctl restart apache2

                        # Vérification de l'existence de l'arborescence avant de la créer
                        if [ ! -d "/var/www/site.local" ]; then
                            mkdir -p /var/www/site.local
                            echo "Arborescence créée."
                        else
                            echo "L'arborescence /var/www/site.local existe déjà."
                        fi

                        # Vérification de l'existence du fichier index avant de le créer
                        if [ ! -f "/var/www/site.local/index.html" ]; then
                            echo "<h1>Test réussi !</h1>" > /var/www/site.local/index.html
                            echo "Fichier index.html créé."
                        else
                            echo "Le fichier index.html existe déjà."
                        fi

                        # Attribution des bonnes permissions
                        chown -R wwwrun:www /var/www/site.local
                        chmod -R 755 /var/www/site.local

                        # Redémarrer Apache pour que tout soit pris en compte
                        systemctl restart apache2

                        echo "Serveur web configuré."

                        #----------Fin de la configuration du service web
                        #------------------------------------------------
                    }

                    break


            elif [ "$config_choice" == "7" ] ; then

                config_mail() {
                    #------------------------------------------
                    #----------Début de la configuration du Mail

                    echo "Configuration du serveur de mail..."

                    # Sauvegarder les fichiers de configuration avant modification
                    cp /etc/postfix/main.cf /etc/postfix/main.cf.bak
                    cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.bak

                    # Configuration de Postfix
                    tee /etc/postfix/main.cf > /dev/null <<EOF
                    myhostname = site.local
                    mydomain = site.local
                    myorigin = \$mydomain
                    mydestination = \$myhostname, localhost.\$mydomain, localhost
                    relayhost =
                    inet_interfaces = all
                    inet_protocols = ipv4
                    smtpd_banner = \$myhostname ESMTP Postfix
                    mynetworks = 127.0.0.0/8
                    mailbox_size_limit = 0
                    recipient_delimiter = +
                    alias_maps = hash:/etc/aliases
                    alias_database = hash:/etc/aliases
                    home_mailbox = Maildir/
EOF
                    # Configurer Dovecot
                    tee /etc/dovecot/dovecot.conf > /dev/null <<EOF
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
                    # Redémarrer les services de Mail
                    if systemctl restart postfix && systemctl restart dovecot; then
                        echo "Serveur de mail configuré et services redémarrés avec succès."
                    else
                        echo "Erreur lors du redémarrage des services de mail."
                    fi

                    #----------------------------------------
                    #----------Fin de la configuration du Mail
                }

                break


            elif [ "$config_choice" == "8" ] ; then

                config_ntp() {
                    #--------------------------------
                    #----------Début du serveur temps

                    echo "Configuration du serveur NTP..."

                    # Sauvegarde du fichier de configuration s'il existe déjà
                    [ -f /etc/chrony.conf ] && cp /etc/chrony.conf /etc/chrony.conf.bak

                    # Configurer chrony.conf
                    tee /etc/chrony.conf > /dev/null <<EOF
                    server 0.pool.ntp.org iburst
                    server 1.pool.ntp.org iburst

                    allow 192.168.0.0/24  #Autorise le réseau local à interroger ce serveur
EOF
                    # Vérifier si chrony est installé et activer le service s'il ne l'est pas déjà
                    if systemctl is-active --quiet chronyd; then
                        echo "Le service NTP est déjà actif. Redémarrage..."
                    else
                        echo "Le service NTP n'est pas actif. Activation du service..."
                        systemctl enable --now chronyd
                    fi

                    # Redémarrer le service NTP
                    systemctl restart chronyd

                    echo "Serveur NTP configuré et service redémarré."

                    #----------Fin du serveur temps
                    #------------------------------
                }

                break


            elif [ "$config_choice" == "9" ] ; then

                config_nfs() {
                    #----------------------------------------------
                    #----------Début de la configuration des backup

                    echo "Configuration de la backup avec le serveur tiers..."

                    [ ! -d /mnt/nfs/var/log ] && mkdir -p /mnt/nfs/var/log
                    [ ! -d /mnt/nfs/var/www ] && mkdir -p /mnt/nfs/var/www
                    [ ! -d /mnt/nfs/var/srv ] && mkdir -p /mnt/nfs/var/srv

                    mount 192.168.0.3:/backups /mnt/nfs/var/log
                    mount 192.168.0.3:/backups /mnt/nfs/var/www
                    mount 192.168.0.3:/backups /mnt/nfs/var/srv

                    tee /etc/fstab > /dev/null <<EOF
                    192.168.0.3:/backups /mnt/nfs/var/log nfs defaults 0 0
                    192.168.0.3:/backups /mnt/nfs/var/www nfs defaults 0 0
                    192.168.0.3:/backups /mnt/nfs/var/srv nfs defaults 0 0
EOF
                    rsync -av --delete /var/log/ /mnt/nfs/var/log/
                    rsync -av --delete /var/www/ /mnt/nfs/var/www/
                    rsync -av --delete /var/srv/ /mnt/nfs/var/srv/

                    touch /usr/local/bin/backup.sh

                    tee /usr/local/bin/backup.sh > /dev/null <<EOF
                    rsync -av --delete /var/log/ /mnt/nfs/var/log/
                    rsync -av --delete /var/www/ /mnt/nfs/var/www/
                    rsync -av --delete /var/srv/ /mnt/nfs/var/srv/
EOF
                    chmod +x /usr/local/bin/backup.sh

                    tee -a /var/spool/cron/crontabs/root > /dev/null <<EOF
                    0 2 * * * /usr/local/bin/backup.sh
EOF
                    echo "Serveurs NFS configurés."

                    #----------Fin de la configuration des backup
                    #--------------------------------------------
                }

                break


            #En cas de mauvaise réponse ou hors-sujet
            else
                echo "Veuillez choisir une réponse valide."
            fi
        done
        break



    elif [ "$main_choice" == "2" ] ; then
        echo -e "Vous avez sélectionné la partie test. Il est recommandé d'avoir d'abord été faire un tour du
        côté config pour avoir matière à tester.\n\n"
        sleep 2
        echo -e "-> Protocole de setup-test lancé avec succès.\n"
        sleep 1

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
                test_all() {
                    test_services
                    test_firewall
                    test_ssh
                    test_dns
                    test_web
                    test_mail
                    test_ntp
                    test_nfs
                }
                echo "Tous les tests sont terminés."

                break
            

            elif [ "$test_choice" == "2" ] ; then

                test_services() {
                    #----------------------------------------
                    #----------Début du test sur les services

                    echo "Début du test sur les services..."

                    # Listes vides pour stocker les erreurs et réussites
                    errors_serv=()
                    success_serv=()

                    # Vérification de l'installation des paquets
                    for pkg in "${packages[@]}"; do
                        if rpm -q "$pkg" &>/dev/null; then
                            success_serv+=("${VERT}Paquet installé : $pkg${RESET}")
                        else
                            errors_serv+=("${ROUGE}Paquet non installé : $pkg${RESET}")
                        fi
                    done

                    # Vérification de l'activation des services
                    for svc in "${services[@]}"; do
                        if systemctl is-active --quiet "$svc"; then
                            success_serv+=("${VERT}Service actif : $svc${RESET}")
                        else
                            errors_serv+=("${ROUGE}Service non actif : $svc${RESET}")
                        fi
                    done

                    # Affichage des résultats
                    for success in "${success_serv[@]}"; do
                        echo -e "${BLEU}$success${RESET}"
                    done

                    for error in "${errors_serv[@]}"; do
                        echo -e "${BLEU}$error${RESET}"
                    done

                    echo "Test sur les services terminé."

                    #----------Fin du test sur les services
                    #--------------------------------------
                }

                break
            

            elif [ "$test_choice" == "3" ] ; then
                
                test_firewall() {
                    #-----------------------------------
                    #----------Début du test du pare-feu

                    echo "Début du test du pare-feu..."

                    # Vérification des ports ouverts
                    for port in "${expected_ports[@]}"; do
                        if firewall-cmd --list-ports | grep -q "$port"; then
                            success_firewall+=("Port $port est ouvert.")
                        else
                            errors_firewall+=("Port $port n'est pas ouvert.")
                        fi
                    done

                    # Affichage des résultats
                    if [ ${#errors_firewall[@]} -eq 0 ]; then
                        echo -e "${GREEN}Tous les ports nécessaires sont ouverts.${RESET}"
                    else
                        for error in "${errors_firewall[@]}"; do
                            echo -e "${RED}$error${RESET}"
                        done
                    fi

                    if [ ${#success_firewall[@]} -gt 0 ]; then
                        for success in "${success_firewall[@]}"; do
                            echo -e "${GREEN}$success${RESET}"
                        done
                    fi

                    echo -e "${BLUE}Test du pare-feu terminé.${RESET}"

                    #----------Fin du test du pare-feu
                    #---------------------------------
                }

                break


            elif [ "$test_choice" == "4" ] ; then

                test_ssh() {
                    #------------------------------
                    #----------Début du test du SSH

                    echo -e "Début du test du SSH..."

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
                    echo -e "${BLUE}Vérification que le service SSH écoute sur le port 2025...${RESET}"
                    if ss -tuln | grep -q ":2025"; then
                        echo -e "${GREEN}Le port 2025 est bien ouvert et SSH écoute dessus.${RESET}"
                        success_ssh+=("SSH écoute sur le port 2025")
                    else
                        echo -e "${RED}Erreur : le port 2025 n'est pas ouvert ou SSH ne l'écoute pas.${RESET}"
                        errors_ssh+=("SSH n'écoute pas sur le port 2025")
                    fi

                    # Vérification que le service SSH est actif
                    if systemctl is-active --quiet sshd; then
                        success_ssh+=("Service SSH est actif.")
                    else
                        errors_ssh+=("Service SSH n'est pas actif.")
                    fi

                    # Affichage des résultats du test SSH
                    for result in "${success_ssh[@]}"; do
                        echo -e "${GREEN}$result${RESET}"
                    done

                    for result in "${errors_ssh[@]}"; do
                        echo -e "${RED}$result${RESET}"
                    done

                    echo -e "${BLUE}Test du SSH terminé.${RESET}"

                    #----------Fin du test sur le SSH
                    #--------------------------------
                }

                break


            elif [ "$test_choice" == "5" ] ; then

                test_dns() {
                    #------------------------------
                    #----------Début du test du DNS

                    echo -e "Début du test sur le DNS..."

                    errors_dns=()
                    success_dns=()

                    # Commencer par vérifier l'état du service bind (named.service)
                    if ! systemctl is-active --quiet named; then
                        errors_dns+=("Le service bind (named.service) n'est actuellement pas actif.")
                    else
                        success_dns+=("Le service bind (named.service) est actif.")
                    fi

                    # Vérification de la résolution du domaine en local
                    if ! dig @127.0.0.1 google.com +short | grep -qE "^(1.1.1.1|8.8.8.8)"; then
                        errors_dns+=("Les requêtes externes ne semblent pas être redirigées vers 1.1.1.1 ou 8.8.8.8.")
                    else
                        success_dns+=("Les requêtes DNS sont correctement redirigées vers 1.1.1.1 ou 8.8.8.8.")
                    fi

                    # Affichage des résultats du test DNS
                    for result in "${success_dns[@]}"; do
                        echo -e "${GREEN}$result${RESET}"
                    done

                    for result in "${errors_dns[@]}"; do
                        echo -e "${RED}$result${RESET}"
                    done

                    echo -e "${BLUE}Test sur le DNS terminé.${RESET}"

                    #----------Fin du test du DNS
                    #----------------------------
                }

                break


            elif [ "$test_choice" == "6" ] ; then

                test_web() {
                    #---------------------------
                    #----------Début du test Web

                    echo -e "Début du test sur le serveur web..."

                    errors_web=()
                    success_web=()

                    # Vérification de l'activation du service apache
                    if ! systemctl is-active --quiet apache2; then
                        errors_web+=("Il semblerait que le service apache2 ne soit pas actuellement actif.")
                    else
                        success_web+=("Le service apache2 est actif.")
                    fi

                    # Vérification de l'ouverture du port 80
                    if ! ss -tln | grep -q ":80 "; then
                        errors_web+=("Le port 80 semble être fermé.")
                    else
                        success_web+=("Le port 80 est ouvert.")
                    fi

                    # Vérification de l'accessibilité du serveur web
                    if ! curl -s --head http://192.168.0.2 | grep -q "200 OK"; then
                        errors_web+=("Le serveur web ne répond pas correctement (pas de réponse http 200).")
                    else
                        success_web+=("Le serveur web répond correctement avec un code http 200.")
                    fi

                    # Affichage des résultats du test web
                    for result in "${success_web[@]}"; do
                        echo -e "${GREEN}$result${RESET}"
                    done

                    for result in "${errors_web[@]}"; do
                        echo -e "${RED}$result${RESET}"
                    done

                    echo -e "${BLUE}Test sur le serveur web terminé.${RESET}"

                    #----------Fin du test Web
                    #-------------------------
                }

                break


            elif [ "$test_choice" == "7" ] ; then

                test_mail() {
                    #-------------------------------------
                    #----------Début du test sur les mails

                    echo "Début du test sur les mails..."

                    errors_mail=()
                    success_mail=()

                    # Vérification de l'activation des services postfix et dovecot
                    for svc in postfix dovecot; do
                        if ! systemctl is-active --quiet "$svc"; then
                            errors_mail+=("Le service $svc n'est pas actif.")
                        else
                            success_mail+=("Le service $svc est actif.")
                        fi
                    done

                    # Vérification de l'ouverture des ports mail
                    ports=("25" "465" "587" "143" "993")
                    for port in "${ports[@]}"; do
                        if ! ss -tln | grep -q ":$port"; then
                            errors_mail+=("Le port $port (mail) n'est pas ouvert.")
                        else
                            success_mail+=("Le port $port (mail) est ouvert.")
                        fi
                    done

                    # Test d'envoi de mail local - Vérification que sendmail est installé
                    if ! command -v sendmail &> /dev/null; then
                        errors_mail+=("La commande sendmail n'est pas disponible.")
                    else
                        echo "Test mail" | sendmail root
                        sleep 2 # Attente pour que le mail soit traîté
                        success_mail+=("L'envoi de mail local fonctionne.")
                    fi

                    # Vérification de la réception du mail
                    if ! mail -H | grep -q "Test mail" && ! doveadmn fetch -u root mailbox INBOX | grep -q "Test mail"; then
                        errors_mail+=("L'envoi ou la réception de mail ne fonctionne pas correctement.")
                    else
                        success_mail+=("L'envoi et la réception de mail fonctionnent correctement.")
                    fi

                    # Affichage des résultats du test mail
                    for result in "${success_mail[@]}"; do
                        echo -e "${GREEN}$result${RESET}"
                    done

                    for result in "${errors_mail[@]}"; do
                        echo -e "${RED}$result${RESET}"
                    done

                    echo -e "${BLUE}Test sur les mails terminé.${RESET}"

                    #----------Fin du test sur les mails
                    #-----------------------------------
                }

                break


            elif [ "$test_choice" == "8" ] ; then

                test_ntp() {
                    #---------------------------
                    #----------Début du test NTP

                    echo "Début du test sur le temps..."

                    errors_tmp=()
                    success_tmp=()

                    # Vérification de l'activation du service chronyd
                    if systemctl is-active --quiet chronyd; then
                        success_tmp+=("Le service chronyd (NTP) est actif.")
                    else
                        errors_tmp+=("Le service chronyd (NTP) ne semble pas être actif.")
                    fi

                    # Vérification de l'ouverture du port NTP (UDP 123)
                    if ss -uln | grep -q ":123"; then
                        success_tmp+=("Le port 123/UDP (NTP) est ouvert.")
                    else
                        errors_tmp+=("Il semblerait que le port 123/UDP (NTP) ne soit pas ouvert.")
                    fi

                    # Vérification de la synchronisation du temps
                    if chronyc tracking | grep -q "Reference ID"; then
                        success_tmp+=("Le serveur NTP est synchronisé avec une source de temps.")
                    else
                        errors_tmp+=("Le serveur NTP ne semble pas synchronisé avec une source de temps.")
                    fi

                    # Vérification de la réponse aux requêtes NTP
                    if ntpq -p 127.0.0.1 &>/dev/null; then
                        success_tmp+=("Le serveur NTP répond aux requêtes.")
                    else
                        errors_tmp+=("Le serveur NTP ne répond pas aux requêtes.")
                    fi

                    # Affichage des résultats du test NTP
                    for result in "${success_tmp[@]}"; do
                        echo -e "${GREEN}$result${RESET}"
                    done

                    for result in "${errors_tmp[@]}"; do
                        echo -e "${RED}$result${RESET}"
                    done

                    echo -e "${BLUE}Test sur le temps terminé.${RESET}"

                    #----------Fin du test NTP
                    #-------------------------
                }

                break


            elif [ "$test_choice" == "9" ] ; then

                test_nfs() {
                    #---------------------------------------
                    #----------Début du test sur les backups

                    # Définition des variables spécifiques
                    SOURCE="/var/www"
                    BACKUP_DIR="/tmp/backup_test"
                    BACKUP_FILE="/tmp/backup_www.tar.gz"
                    RESTORE_DIR="/tmp/www_restored"

                    errors_backup=()
                    success_backup=()

                    echo "Début du test sur les backups..." 

                    # Vérifier si le dossier source existe
                    if [ ! -d "$SOURCE" ]; then
                        errors_backup+=("Le dossier source $SOURCE n'existe pas.")
                    else
                        success_backup+=("Le dossier source $SOURCE existe.")
                    fi

                    # Si le dossier source existe, on continue
                    if [ -d "$SOURCE" ]; then
                        # Création d'une copie temporaire pour le test
                        echo "Création d'une copie temporaire de $SOURCE..."
                        cp -a "$SOURCE" "$BACKUP_DIR"

                        # Vérification de la copie
                        if [ ! -d "$BACKUP_DIR" ]; then
                            errors_backup+=("Échec de la copie temporaire.")
                        else
                            success_backup+=("La copie temporaire a été créée avec succès.")
                        fi

                        # Sauvegarde de la copie
                        echo "Réalisation de la sauvegarde test."
                        tar -czf "$BACKUP_FILE" -C "$BACKUP_DIR" .

                        # Vérification de la sauvegarde
                        if [ ! -f "$BACKUP_FILE" ]; then
                            errors_backup+=("Échec de la création de la sauvegarde.")
                        else
                            success_backup+=("La sauvegarde a été créée avec succès.")
                        fi

                        # Suppression de la copie temporaire
                        echo "Suppression de la copie temporaire..."
                        rm -rf "$BACKUP_DIR"

                        # Vérification de la suppression de la copie temporaire
                        if [ -d "$BACKUP_DIR" ]; then
                            errors_backup+=("Échec de la suppression de la copie temporaire.")
                        else
                            success_backup+=("La copie temporaire a été supprimée avec succès.")
                        fi

                        # Restauration de la sauvegarde
                        echo "Restauration de la sauvegarde..."
                        mkdir -p "$RESTORE_DIR"
                        tar -xzf "$BACKUP_FILE" -C "$RESTORE_DIR"

                        # Vérification de la restauration
                        if [ ! "$(ls -A "$RESTORE_DIR")" ]; then
                            errors_backup+=("Échec de la restauration des fichiers.")
                        else
                            success_backup+=("La restauration des fichiers a réussi.")
                        fi
                    fi

                    # Affichage des résultats du test de backup
                    for result in "${success_backup[@]}"; do
                        echo -e "${GREEN}$result${RESET}"
                    done

                    for result in "${errors_backup[@]}"; do
                        echo -e "${RED}$result${RESET}"
                    done

                    echo -e "${BLUE}Test unitaire sur la backup terminé.${RESET}"

                    #----------Fin du test unitaire sur la backup
                    #--------------------------------------------
                }

                break

                
            #En cas de mauvaise réponse ou hors-sujet
            else
                echo "Veuillez choisir une réponse valide."
            fi
        done
        break

    else
        printf "Veuillez sélectionner une entrée valable.\n\n"

    fi

done
