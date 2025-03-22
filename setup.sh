#!/bin/bash

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
                break


            elif [ "$config_choice" == "2" ] ; then

                echo -e "Configuration du serveur en cours..."
                sleep 2


                #-----------------------------------------------
                #----Début de l'installation des services requis

                #Liste des paquets à installer
                packages=("apache2" "btop" "openssh" "nmap" "nfs-kernel-server" "nfs-client" "bind" "bind-utils" "chrony" "postfix" "dovecot")

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
                services=("sshd" "named" "apache2" "postfix" "dovecot" "chronyd")

                # Démarrer les services
                for service in "${services[@]}"; do
                    if ! systemctl is-active --quiet "$service"; then
                        echo -e "Démarrage du service $service..."
                        systemctl enable --now "$service"
                    else
                        echo -e "$service est déjà en cours d'exécution."
                    fi
                done

                #Changement du port SSH
                sed -i 's/^Port 22/Port 2025/' /etc/ssh/sshd_config

                #-----------------------------------------------
                #-----------Fin du démarrage des services requis


            elif [ "$config_choice" == "3" ] ; then

                #-----------------------------------------------
                #----------Début de la configuration du pare-feu

                #Service SSH
                firewall-cmd --permanent --add-port=2025/tcp #->Port choisi pour le SSH
                firewall-cmd --permanent --remove-port=22/tcp #->On retire le port SSH par défaut

                #Service web
                firewall-cmd --permanent --add-port=80/tcp #->HTTP
                firewall-cmd --permanent --add-port=80/tcp #->HTTPS

                #Service DNS
                firewall-cmd --permanent --add-port=53/tcp #->requêtes TCP (bah oui...)
                firewall-cmd --permanent --add-port=53/udp #->requêtes UDP

                #Service mail
                firewall-cmd --permanent --add-port=25/tcp #->SMTP (envoie mail)
                firewall-cmd --permanent --add-port=465/tcp #->SMTPS (SMTP sécurisé)
                firewall-cmd --permanent --add-port=587/tcp #->Submission (authentification SMTP)
                firewall-cmd --permanent --add-port=993/tcp #->IMAPS (réception sécurisée via Dovecot)
                firewall-cmd --permanent --add-port=995/tcp #->POP3S (récepetion sécurisée via POP3)

                #Service NTP
                firewall-cmd --permanent --add-port=123/udp #->NTP (Network Time Protocol)

                #Service NFS
                firewall-cmd --permanent --add-port=2049/tcp
                firewall-cmd --permanent --add-port=2049/udp

                #Recharge de la configuration
                firewall-cmd --reload

                #----------Fin de la configuration du pare-feu
                #---------------------------------------------


            elif [ "$config_choice" == "4" ] ; then

                #------------------------------------------
                #----------Début de la configuration du SSH


                # Sauvegarder le fichier de configuration avant modification
                cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

                # Redémarrer le service SSH
                if sudo systemctl restart sshd; then
                    echo "Service SSH redémarré avec succès."
                else
                    echo "Erreur lors du redémarrage du service SSH."
                fi

                echo "Service SSH configuré. Le port dédié est 2025."

                #----------Fin de la configuation du SSH
                #---------------------------------------


            elif [ "$config_choice" == "5" ] ; then

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
                if sudo systemctl restart named.service; then
                    echo "Serveur DNS configuré et service redémarré avec succès."
                else
                    echo "Erreur lors du redémarrage du service DNS."
                fi

                #----------Fin de la configuration du DNS
                #----------------------------------------


            elif [ "$config_choice" == "6" ] ; then

                #--------------------------------------------------
                #----------Début de la configuration du service web

                echo "Configuration du serveur web..."

                # Création du fichier de configuration de VirtualHost
                sudo tee /etc/apache2/vhosts.d/site.local.conf > /dev/null <<EOF
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


                break

            #En cas de mauvaise réponse ou hors-sujet
            else
                echo "Veuillez choisir une réponse valide."

            fi
        done
        break

    elif [ "$main_choice" == "2" ] ; then
        printf "Vous avez sélectionné la partie test. Il est recommandé d'avoir d'abord été faire un tour du
        côté config pour avoir matière à tester.\n\n"
        break

    else
        printf "Veuillez sélectionner une entrée valable.\n\n"

    fi
done