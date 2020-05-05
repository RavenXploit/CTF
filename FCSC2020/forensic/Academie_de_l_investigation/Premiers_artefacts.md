![FCSC 2020 LOGO](../../logo.png)

# Académie de l'investigation - Premiers artéfacts

![Badge introduction](https://img.shields.io/static/v1?label=Catégorie%20principale&message=Forensique&color=E22244&style=for-the-badge)
![Badge introduction](https://img.shields.io/static/v1?label=Catégories%20Complémentaires&message=GNU/Linux,%20Mémoire,%20DFIR&color=091B33&style=for-the-badge)


# Énoncé 

>Pour avancer dans l'analyse, vous devez retrouver :
>
>- Le nom de processus ayant le PID 1254.
>- La commande exacte qui a été exécutée le 2020-03-26 23:29:19 UTC.
>- Le nombre de connexions réseau `TCP` et `UDP` établies lors du dump avec `Peer Address` unique
>
>Format du flag : FCSC{nom_du_processus:une_commande:n}
>
>Le fichier de dump à analyser est identique au challenge C'est la rentrée.



## Introduction

Ce challenge est le second de de la série "l'Académie de l'investigation".

Celle-ci était composée des challenges suivants : 

* [C'est la rentrée](./C_est_la_rentree.md) 
* [Premiers artéfacts](./Premiers_artefacts.md) 
* [Porte dérobée](./porte_derobee.md) 
* Rédaction
* Administration
* Dans les nuages


Ce challenge fera l'objet d'une rapide présentation de volatility ainsi que des méthodes qui permettent de construire les profiles d'analyses.

## Présentation de volatility

L’analyse de la mémoire est une part très importante des investigations forensics. 
Elle peut révéler des processus malicieux, des activités réseaux suspectes ,des clés de registre, des mots de passe, etc.

L’outil les plus populaires pour l’analyse des mémoires RAM est [Volatility](https://github.com/volatilityfoundation/volatility).
Cette plateforme Open Source, implémentée dans le language Python, supporte plusieurs formats d’image mémoires :

  - Raw linear sample (dd)
  - Hibernation file (from Windows 7 and earlier)
  - Crash dump file
  - VirtualBox ELF64 core dump
  - VMware saved state and snapshot files
  - EWF format (E01) 
  - LiME format
  - Mach-O file format
  - QEMU virtual machine dumps
  - Firewire 
  - HPAK (FDPro)

Volatility a la capacité d'analyser des dumps mémoires issus des trois principaux sytèmes d'exploitation, à savoir Windows, Linux et Mac OS, mais également Android.

Pour cela, volatility se base sur la notion de `profile`. 


## Création du profil d'analyse

Un profil correspondant à la version du noyau du système que vous souhaitez analyser. 

Un profil Linux est essentiellement un fichier zip contenant des informations sur les structures de données du noyau et les symboles de débogage. 
Ces données et symboles sont utilisées par Volatility pour localiser les informations critiques et les analyser une fois trouvées. 

Si un profil préétabli n'existe pas, il est nécéssaire de créer le notre.

Bien évidemment, challenge de l'ANSSI oblige, nous devons créer notre profil pour effectuer l'analyse.

Dans un premier temps, il est nécéssaire de monter un système identique. 
En effet, l'erreur la plus courante en matière d'analyse de mémoire de Linux consiste à établir un profil pour un système autre que la machine que vous voulez analyser. 
Par exemple, vous ne pouvez pas construire un profil pour un système Debian 2.6.32 afin d'analyser un vidage de mémoire à partir de Mandrake 2.6.32. 
De même, vous ne pouvez pas construire un profil pour un système SuSE 2.5.35 pour analyser un vidage de mémoire à partir de SuSE 2.6.42. 

Vous devez vous assurer que le profil que vous créez correspond au système cible : 
- même distribution Linux 
- même version pour le noyau
- architecture du processeur (32-bit, 64-bit, etc) identique

Nous allons donc récupérer les informations qui concerne le système à analyser. 
Ces données devaient être récupérée pour le challenge [C'est la rentrée](./C_est_la_rentree.md).

Nous commençons par récupérer la version du kernel : 

```bash
RavenXploit@pc:~/FCSC/forensic$ strings dmp.mem | grep "Linux version"
Linux version 5.4.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 9.2.1 20200203 (Debian 9.2.1-28)) #1 SMP Debian 5.4.19-1 (2020-02-13)
Linux version 5.4.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 9.2.1 20200203 (Debian 9.2.1-28)) #1 SMP Debian 5.4.19-1 (2020-02-13)
```

Nous pouvons voir que nous avons à faire à une Debian, on récupère la version exacte: 

```bash
RavenXploit@pc:~/FCSC/forensic$ strings dmp.mem | grep -e jessy -e buster -e bullseye
Linux 5.4.0-4-amd64 Debian GNU/Linux bullseye/sid
Debian GNU/Linux bullseye/sid
built on Debian bullseye/sid, running on Debian bullseye/sid Chrome/80.0.3987.132 Linux x86_64
built on Debian bullseye/sid, running on Debian bullseye/sid Chrome/80.0.3987.132 Linux x86_64
Debian GNU/Linux bullseye/sid
```

La version bullseye/sid est ici utilisée. Il s'agit d'une version de Debian en cours de développement (lors de la rédaction de ce WU).

Nous récupérons l'iso sur le site de Debian et nous installons le sytème d'exploitation dans une solution de virtualisation.
Dans mon cas j'ai utilisé QEMU mais cela peut-être fait avec la solution de votre choix.
Je ne détaillerais pas les étapes d'installation dans ce WU étant donné qu'il s'agit de simples opérations de base en administration de systèmes.

Une fois votre système installé, nous commençons par vérifier la version de notre kernel : 

```
root@challenge:~$ uname -a
Linux challenge 5.4.0-4-amd64 #1 SMP Debian 5.4.19-1 (2020-02-13) x86_64 GNU/Linux
```

Nous avons bien la version de kernel souhaité. Si cela n'avait pas été le cas nous aurions dû compiler nous même notre kernel.

Par la suite, il est nécéssaire d'installer les paquets suivants :

* dwarfdump
* GCC/make
* les headers pour la construction des modules du noyau
* git

La blague du jour fût de s'apercevoir que les headers n'étaient pas disponibles dans les dépots de Bullseye...

En cherchant sur le site de Debian j'ai pu voir que ceux-ci étaient disponibles dans les backports de Buster. 

On modifie donc le fichier /etc/apt/sources.list pour y ajouter la ligne suivante : 

```bash
$ deb http://deb.debian.org/debian buster-backports main
```

Puis on effectue l'installation des headers : 

```bash
$ apt update
$ apt install linux-headers-5.4.0-0.bpo.4-all-amd64
```

Nous allons maintenant pouvoir créer notre profil.
Pour cela, nous téléchargeons volatility sur notre machine virtuelle : 

```bash
$ git clone https://github.com/volatilityfoundation/volatility.git
$ cd volatility/tools/linux/
```

Nous avons dans ce dossier le fichier Makefile suivant : 

```bash 
linux git:(master) ✗ cat Makefile 
obj-m += module.o
KDIR ?= /
KVER ?= $(shell uname -r)

-include version.mk

all: dwarf 

dwarf: module.c
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build CONFIG_DEBUG_INFO=y M="$(PWD)" modules
	dwarfdump -di module.ko > module.dwarf
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M="$(PWD)" clean

clean:
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M="$(PWD)" clean
	rm -f module.dwarf

```

Nous allons effectuer une petite modification au sein du fichier Makefile afin de faire correspondre la variable `KVER` à notre système.
En effet, ayant installé les headers depuis les backports, ceux-ci se situent dans le dossier `/lib/modules/5.4.0-0.bpo.4-amd64/build` et non dans `lib/modules/5.4.0-4-amd64/build`. 

Il suffit donc de modifier la ligne suivant : 

```bash
KVER ?= "5.4.0-0.bpo.4-amd64"
```

Nous pouvons maintenant créer les vtypes (structures de données du noyau) en compilant.

```bash
$ make                      
make -C //lib/modules/"5.4.0-0.bpo.4-amd64"/build CONFIG_DEBUG_INFO=y M="/root/volatility/tools/linux" modules
make[1] : on entre dans le répertoire « /usr/src/linux-headers-5.4.0-0.bpo.4-amd64 »
  CC [M]  /root/volatility/tools/linux/module.o
  Building modules, stage 2.
  MODPOST 1 modules
WARNING: modpost: missing MODULE_LICENSE() in /root/volatility/tools/linux/module.o
see include/linux/module.h for more information
  CC [M]  /root/volatility/tools/linux/module.mod.o
  LD [M]  /root/volatility/tools/linux/module.ko
make[1] : on quitte le répertoire « /usr/src/linux-headers-5.4.0-0.bpo.4-amd64 »
dwarfdump -di module.ko > module.dwarf
make -C //lib/modules/"5.4.0-0.bpo.4-amd64"/build M="/root/volatility/tools/linux" clean
make[1] : on entre dans le répertoire « /usr/src/linux-headers-5.4.0-0.bpo.4-amd64 »
  CLEAN   /root/volatility/tools/linux/Module.symvers
make[1] : on quitte le répertoire « /usr/src/linux-headers-5.4.0-0.bpo.4-amd64 »
```

Les vtypes sont créés dans le fichier nommé  `module.dwarf`.

Les symboles quand à eux sont contenus dans le fichier `System.map`. 
Ce fichier se trouve presque toujours dans le répertoire /boot de l'installation. Sinon vous pouvez le générer vous-même en exécutant "nm" sur le fichier vmlinux du noyau. 
Si vous avez déjà mis à jour le noyau sur votre système dans le passé, le répertoire /boot peut contenir plusieurs fichiers System.map - assurez-vous donc de choisir le bon.

Pour créer notre profil nous allons mettre dans une archive zip les élèments suivants :
* les vtypes 
* les symboles

```bash 
zip debian_5.4.0-4-amd64.zip module.dwarf  /boot/System.map-5.4.0-4-amd64
```

Une fois cette archive crée, il est nécessaire de récupérer celle-ci sur votre machine hôte et de la placer dans `volatility/plugins/overlays/linux/`.

```bash
RavenXploit@pc:~/FCSC/forensic$ sudo mv debian_5.4.0-4-amd64.zip /usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/
```

Il nous reste plus qu'à vérifier que le profil est bien chargé par volatility : 

```bash
RavenXploit@pc:~/FCSC/forensic$ volatility --info | grep Linuxdebian_5_4_0-4-amd64x64
Volatility Foundation Volatility Framework 2.6
Linuxdebian_5_4_0-4-amd64x64 - A Profile for Linux debian_5.4.0-4-amd64 x64
```

Il est maintenant temps de passer à la résolution de ce challenge ! 

## Résolution du challenge


Vous pouvez obtenir les différentes commandes disponibles pour le profil créé via l'option -h  : 

```bash
RavenXploit@pc:~/FCSC/forensic$ volatility -f dmp.mem --profile=Linuxdebian_5_4_0-4-amd64x64 -h
```

La première partie de notre flag consiste à récupérer le nom du processus ayant le PID 1254.
Nous allons utiliser la commande `linux_psscan` pour cela :

```bash
RavenXploit@pc:~/FCSC/forensic$ volatility -f dmp.mem --profile=Linuxdebian_5_4_0-4-amd64x64 linux_psscan | grep 1254
Volatility Foundation Volatility Framework 2.6
0x000000003fdccd80 pool-xfconfd         1254            -               -1              -1     0x0fd08ee88ee08ec0 -

```

Le processus est donc pool-xfconfd.

Concernant la commande exacte qui a été exécutée le 2020-03-26 23:29:19 UTC, nous utilisons la fonctionnalité `linux_bash` qui permet de récupérer l'historique des commandes présentes dans la mémoire (dû au chargement du processus bash).

```bash 
RavenXploit@pc:~/FCSC/forensic$ volatility -f dmp.mem --profile=Linuxdebian_5_4_0-4-amd64x64 linux_bash
Volatility Foundation Volatility Framework 2.6
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
    1523 bash                 2020-03-26 23:24:18 UTC+0000   rm .bash_history 
    1523 bash                 2020-03-26 23:24:18 UTC+0000   exit
    1523 bash                 2020-03-26 23:24:18 UTC+0000   vim /home/Lesage/.bash_history 
    1523 bash                 2020-03-26 23:24:27 UTC+0000   ss -laupt
    1523 bash                 2020-03-26 23:26:06 UTC+0000   rkhunter -c
    1523 bash                 2020-03-26 23:29:19 UTC+0000   nmap -sS -sV 10.42.42.0/24
    1523 bash                 2020-03-26 23:31:31 UTC+0000   ?+??U
    1523 bash                 2020-03-26 23:31:31 UTC+0000   ip -c addr
    1523 bash                 2020-03-26 23:38:00 UTC+0000   swapoff -a
    1523 bash                 2020-03-26 23:38:05 UTC+0000   swapon -a
    1523 bash                 2020-03-26 23:40:18 UTC+0000   ls
    1523 bash                 2020-03-26 23:40:23 UTC+0000   cat LiME.txt 
    1523 bash                 2020-03-26 23:40:33 UTC+0000   cd LiME/src/
    1523 bash                 2020-03-26 23:40:54 UTC+0000   
    1523 bash                 2020-03-26 23:40:54 UTC+0000   insmod lime-5.4.0-4-amd64.ko "path=/dmp.mem format=lime timeout=0"
``` 

Enfin nous utilisons l'option `linux_netstat` pour obtenir Le nombre d'IP-DST unique en communications TCP établies (état ESTABLISHED) lors du dump.

```bash
RavenXploit@pc:~/FCSC/forensic$ volatility -f dmp.mem --profile=Linuxdebian_5_4_0-4-amd64x64 linux_netstat | grep -e TCP | grep -e ESTABLISHED | sort -u -k4,4         
Volatility Foundation Volatility Framework 2.6
TCP      10.42.42.131    :53190 104.124.192.89  :  443 ESTABLISHED              chromium/119187
TCP      10.42.42.131    :51858 10.42.42.128    :  445 ESTABLISHED             smbclient/119577
TCP      10.42.42.131    :57000 10.42.42.134    :   22 ESTABLISHED                   ssh/119468
TCP      10.42.42.131    :50612 104.93.255.199  :  443 ESTABLISHED              chromium/119187
TCP      10.42.42.131    :36970 116.203.52.118  :  443 ESTABLISHED                   tor/706  
TCP      127.0.0.1       :38498 127.0.0.1       :34243 ESTABLISHED                   cli/119514
TCP      10.42.42.131    :55224 151.101.121.140 :  443 ESTABLISHED              chromium/119187
TCP      10.42.42.131    :37252 163.172.182.147 :  443 ESTABLISHED                   tor/706  
TCP      10.42.42.131    :58772 185.199.111.154 :  443 ESTABLISHED              chromium/119187
TCP      10.42.42.131    :47106 216.58.206.226  :  443 ESTABLISHED              chromium/119187
TCP      10.42.42.131    :38186 216.58.213.142  :  443 ESTABLISHED              chromium/119187
TCP      10.42.42.131    :45652 35.190.72.21    :  443 ESTABLISHED              chromium/119187


RavenXploit@pc:~/FCSC/forensic$ volatility -f dmp.mem --profile=Linuxdebian_5_4_0-4-amd64x64 linux_netstat | grep -e TCP | grep -e ESTABLISHED | sort -u -k4,4  | wc -l
12
```

```bash 
RavenXploit@pc:~/FCSC/forensic$ volatility -f dmp.mem --profile=Linuxdebian_5_4_0-4-amd64x64 linux_netstat | grep -e UDP 
Volatility Foundation Volatility Framework 2.6
UDP      0.0.0.0         : 5353 0.0.0.0         :    0                      avahi-daemon/633  
UDP      ::              : 5353 ::              :    0                      avahi-daemon/633  
UDP      0.0.0.0         :48868 0.0.0.0         :    0                      avahi-daemon/633  
UDP      ::              :56069 ::              :    0                      avahi-daemon/633  
UDP      10.42.42.131    :   68 10.42.42.254    :   67                    NetworkManager/636  
UDP      ::1             :   53 ::              :    0                           unbound/695  
UDP      127.0.0.1       :   53 0.0.0.0         :    0                           unbound/695  
UDP      224.0.0.251     : 5353 0.0.0.0         :    0                          chromium/119148
```

Nous pouvons voir que nous avons une seule connexion UDP vers un peer.

On récapitule nous avons donc : 
* Le nom de processus ayant le PID `1254` => pool-xfconfd
* La commande exacte qui a été exécutée le `2020-03-26 23:29:19 UTC` => nmap -sS -sV 10.42.42.0/24
* Le nombre de connexions réseau `TCP` et `UDP` établies lors du dump avec `Peer Address` unique =>  12 TCP + 1 UDP = 13

Voici donc notre flag :  `FCSC{pool-xfconfd:nmap -sS -sV 10.42.42.0/24:13}`

<p align="center">
  <img src="./medias/flag.jpeg">
</p>
