![FCSC 2020 LOGO](../../logo.png)

# Académie de l'investigation - C'est la rentrée

![Badge introduction](https://img.shields.io/static/v1?label=Catégorie%20principale&message=Forensique&color=E22244&style=for-the-badge)
![Badge introduction](https://img.shields.io/static/v1?label=Catégories%20Complémentaires&message=GNU/Linux,%20Mémoire,%20DFIR&color=091B33&style=for-the-badge)


# Énoncé 
>Bienvenue à l'académie de l'investigation numérique ! Votre mission, valider un maximum d'étapes de cette série afin de démontrer votre dextérité en analyse mémoire GNU/Linux.
>
>Première étape : retrouvez le HOSTNAME, le nom de l'utilisateur authentifié lors du dump et la version de Linux sur lequel le dump a été fait.
>
>Format du flag : FCSC{hostname:user:x.x.x-x-amdxx}
>
>SHA256(dmp.tar.gz) = 8db3935afe4ba55a18f9b68abbf9019609ecac0720c73ce7e54b2931554c4ef0 - 209M
>
>SHA256(dmp.mem) = 3012655179f7519506aa851ffaff7e5589d9aa28e24d587d046d3fe8fc7da6b0 - 1.3G


## Introduction

Ce challenge est le premier de de la série "l'Académie de l'investigation".

Celle-ci était composée des challenges suivants : 

* C'est la rentrée
* Porte dérobée
* Rédaction
* Administration
* Premiers artéfacts
* Dans les nuages



## Résolution

Nous commençons dans un premier temps par désarchiver le fichier téléchargé :

```bash
RavenXploit@pc:~/FCSC$ tar -zxvf dmp.tar.gz
dmp.mem
```

Nous observons qu'il s'agit d'un fichier de données brut : 

```bash
RavenXploit@pc:~/FCSC$ file dmp.mem 
dmp.mem: data
```

Nous pouvons donc très rapidement résoudre ce challenge grâce aux commandes strings et grep. 

Pour la recherche du hostname : 

```bash
RavenXploit@pc:~/FCSC/forensic$ strings dmp.mem | grep HOSTNAME
XAUTHLOCALHOSTNAME=
RESOLVE-HOSTNAME%s %s
PWMGR_NUM_PASSWORDS_PER_HOSTNAME
XAUTHLOCALHOSTNAME
PWMGR_NUM_PASSWORDS_PER_HOSTNAME
NM_DHCP_HOSTNAME_FLAG_NONE
HOSTNAME
NO_HOSTNAME_SPECIFIED
XAUTHLOCALHOSTNAME
HOSTNAME
HOSTNAME
RESOLVE-HOSTNAME%s %s
HOSTNAME
_HOSTNAME=challenge.fcsc
HOSTNAME
```

Nous trouvons le hostname qui est "challenge.fcsc"


Concernant l'utilisateur, j'ai utilisé une part de guessing.
Nous savons que, généralement, chaque utilisateurs possèdent un home directory. Utilisons ça à notre avantage : 

```bash
RavenXploit@pc:~/FCSC/forensic$ strings dmp.mem | grep /home/ 
HOME=/home/Lesage
/home/Lesage/.config
/home/Lesage/.config
/home/Lesage/.cache
/home/Lesage/.config/systemd/user.control
/home/Lesage/.config/chromium/Default/Network Action Predictor
/home/Lesage/.config/chromium/Default/Shortcuts
/home/Lesage
[...]
```

Notre utilisateur est donc Lesage.

Enfin pour la version linux : 

```bash
RavenXploit@pc:~/FCSC/forensic$ strings dmp.mem | grep "Linux version"
Linux version 5.4.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 9.2.1 20200203 (Debian 9.2.1-28)) #1 SMP Debian 5.4.19-1 (2020-02-13)
Linux version 5.4.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 9.2.1 20200203 (Debian 9.2.1-28)) #1 SMP Debian 5.4.19-1 (2020-02-13)
```

Nous en profitons également pour récupérer les informations liées à la version de debian: 

```bash
RavenXploit@pc:~/FCSC/forensic$ strings dmp.mem | grep -e jessy -e buster -e bullseye
Linux 5.4.0-4-amd64 Debian GNU/Linux bullseye/sid
Debian GNU/Linux bullseye/sid
built on Debian bullseye/sid, running on Debian bullseye/sid Chrome/80.0.3987.132 Linux x86_64
built on Debian bullseye/sid, running on Debian bullseye/sid Chrome/80.0.3987.132 Linux x86_64
Debian GNU/Linux bullseye/sid
```

Ceci nous sera utile pour les challenges suivants.

Nous avons donc : 
* hostname : challenge.fcsc
* utilisateur : Lesage
* version de linux : 5.4.0-4-amd64

Ce qui donne le flag : FCSC{challenge.fcsc:Lesage:5.4.0-4-amd64}

![FCSC 2020 LOGO](medias/meme1.png)