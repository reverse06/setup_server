# setup_server
Everything is in the name...

Ce script permet de configurer et de tester un serveur avec divers services comme SSH, DNS, Web, Mail, et NFS. Il est conçu pour être utilisé sur une machine avec OpenSUSE. Il permet d'installer, configurer, et tester les services de manière automatisée.
Prérequis

    Une machine sous OpenSUSE (ou une distribution compatible avec les commandes zypper et systemctl).

    Un accès root ou des privilèges sudo pour l'installation et la configuration des services.

    Le script doit être exécuté avec les droits appropriés pour les modifications système.

Installation

    Installez direcement le script depuis cette page ou avec un `git clone "url"`.

Rendez le script exécutable :

    chmod +x setup_serveur.sh

**Utilisation**

    Lancez le script en tant que super-utilisateur (root) ou avec sudo :

    ./setup_serveur.sh

    Choisissez l'option de configuration ou de test :

        [1] Configuration : Configure le serveur en installant et en paramétrant les services (SSH, DNS, Web, Mail, NFS, etc.).

        [2] Test : Vous permet de tester les services après la configuration (vérification de leur bon fonctionnement).

    Suivez les instructions dans le terminal pour chaque partie de la configuration, selon vos besoins.

**Partie Configuration :**

Lorsque vous sélectionnez l'option [1], le script vous propose plusieurs sous-options pour configurer différents services. Vous pouvez choisir de configurer :

    [1] Tout : Configure tous les services.

    [2] Services : Installe et configure les services nécessaires (Apache, SSH, NFS, etc.).

    [3] Pare-feu : Configure les règles du pare-feu.

    [4] SSH : Configure la connecton SSH.

    [5] DNS : Configure un serveur DNS avec des zones.

    [6] Web : Configure un serveur web avec Apache.

    [7] Mail : Configure les services de mail (Postfix, Dovecot).

    [8] NTP : Configure le service de synchronisation horaire.

    [9] NFS : Configure le service NFS.

**Partie Test :**

Une fois la configuration terminée, vous pouvez utiliser l'option [2] Test pour vérifier que tous les services fonctionnent comme prévu.
Détails techniques

    Services installés :

        SSH (port 2025) pour l'accès sécurisé à distance.

        DNS pour la gestion des zones DNS locales.

        Web (Apache) pour servir des pages web.

        Mail (Postfix, Dovecot) pour la gestion des emails.

        NTP pour synchroniser l'heure.

        NFS pour le partage de fichiers.

    Pare-feu : Les ports nécessaires pour chaque service sont ouverts dans le pare-feu (HTTP, HTTPS, DNS, SSH, etc.).

Avertissements

    Assurez-vous que les services n'entrent pas en conflit avec des configurations existantes sur votre serveur.

    Les fichiers de configuration existants sont sauvegardés avant toute modification.

**Personnalisation**

Le script est entièrement modifiable selon vos besoins. Vous pouvez modifier les paramètres dans le code pour personnaliser davantage la configuration des services.

**Contribuer**

Si vous souhaitez contribuer à l'amélioration de ce script, n'hésitez pas à proposer des modifications ou à soumettre des pull requests via GitHub.
Licence

Ce script est sous licence MIT. Vous êtes libre de l'utiliser, de le modifier et de le distribuer.
