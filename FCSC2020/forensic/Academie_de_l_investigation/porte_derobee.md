![FCSC 2020 LOGO](../../logo.png)

# Académie de l'investigation - Porte dérobée

![Badge introduction](https://img.shields.io/static/v1?label=Catégorie%20principale&message=Forensique&color=E22244&style=for-the-badge)
![Badge introduction](https://img.shields.io/static/v1?label=Catégories%20Complémentaires&message=GNU/Linux,%20Backdoor,%20DFIR&color=091B33&style=for-the-badge)


# Énoncé

> Un poste distant est connecté au poste en cours d'analyse via une porte dérobée avec la capacité d'exécuter des commandes.
> * Quel est le numéro de port à l'écoute de cette connexion ?
> * Quelle est l'adresse IP distante connectée au moment du dump ?
> * Quel est l'horodatage de la création du processus en UTC de cette porte dérobée ?
>
> Format du flag : FCSC{port:IP:YYYY-MM-DD HH:MM:SS}
> 
> Le fichier de dump à analyser est identique au challenge C'est la rentrée.


## Introduction

Ce challenge est le troisième de de la série "l'Académie de l'investigation".

Celle-ci était composée des challenges suivants : 

* [C'est la rentrée](./C_est_la_rentree.md)
* [Premiers artéfacts](./Premiers_artefacts.md) 
* [Porte dérobée](./porte_derobee.md) 
* Rédaction
* Administration
* Dans les nuages



## Résolution

Ce challenge se résout très rapidement grâce à volatility. 

> Si vous ne savez pas comment préparer l'analyse, je vous invite à lire le write-up [Premiers artéfacts](./Premiers_artefacts.md) dans lequel je détaille la mise en place de l'environnement.

Nous allons profiter du plugin `linux_netstat` qui est disponible pour le profil précédemment créé. 
Nous recherchons dans un premier temps le port en écoute ("LISTEN") : 

```bash
volatility -f dmp.mem --profile=Linuxdebian_5_4_0-4-amd64x64 linux_netstat | grep LISTEN          
Volatility Foundation Volatility Framework 2.6
TCP      ::              :36280 ::              :    0 LISTEN                       ncat/119711
TCP      0.0.0.0         :36280 0.0.0.0         :    0 LISTEN                       ncat/119711
```

Nous avons donc ici à faire à un `netcat qui tourne sur le port TCP 36280`. 

Pour ceux qui ne connaissent pas ce petit couteau suisse, voici ce que dit Wikipedia à ce sujet ;) 

> Netcat, également abrégé nc, est un utilitaire permettant d'ouvrir des connexions réseau, que ce soit UDP ou TCP. Il est conçu pour être incorporé aisément dans un large éventail d'applications. En raison de sa polyvalence, netcat est aussi appelé le « couteau suisse du TCP/IP ». Il existe sur plusieurs systèmes d'exploitation et s'utilise en ligne de commande.
>
> Il peut être utilisé pour connaître l'état des ports à la façon d'un scan de ports. Les paramètres peuvent comprendre une plage de ports et une variation aléatoire plutôt qu'un scan d'ordre décroissant par défaut. Il existe aussi une option qui permet d'envoyer des paquets source-routed, des paquets qui sont envoyés via des routeurs dont on spécifie les adresses IP. Mais la flexibilité de cet outil permet des usages plus exotiques : transferts de fichiers, backdoor, serveur proxy basique, ou encore messagerie instantanée.

Dans notre cas nous avons à faire à une utilisation exotique où l'attaquant utilise netcat comme un point d'entrée (backdoor).

Nous allons maintenant chercher l'adresse de l'attaquant. Pour cela, l'option `linux_netstat` est à nouveau utilisée, mais nous allons cette fois nous concentrer sur le numéro du port en écoute :


```bash
volatility -f dmp.mem --profile=Linuxdebian_5_4_0-4-amd64x64 linux_netstat | grep 36280
Volatility Foundation Volatility Framework 2.6
TCP      fd:6663:7363:1000:c10b:6374:25f:dc37:36280 fd:6663:7363:1000:55cf:b9c6:f41d:cc24:58014 ESTABLISHED                  ncat/1515 
TCP      fd:6663:7363:1000:c10b:6374:25f:dc37:36280 fd:6663:7363:1000:55cf:b9c6:f41d:cc24:58014 ESTABLISHED                    sh/119511
TCP      ::              :36280 ::              :    0 LISTEN                       ncat/119711
TCP      0.0.0.0         :36280 0.0.0.0         :    0 LISTEN                       ncat/119711
```

Notre attaquant était donc connecté à la machine, lors du dump mémoire, depuis l'adresse IPv6 `fd:6663:7363:1000:55cf:b9c6:f41d:cc24`.

Il ne nous reste donc plus qu'à retrouver l'heure de création du processus netcat pour terminer ce challenge.

Nous faisons cette fois appel au plugin `linux_pslist` :

```bash
volatility -f dmp.mem --profile=Linuxdebian_5_4_0-4-amd64x64 linux_pslist | grep ncat
Volatility Foundation Volatility Framework 2.6
0xffff9d72c014be00 ncat                 1515            1513            1001            1001   0x000000003e3d0000 2020-03-26 23:24:20 UTC+0000
0xffff9d7284928000 ncat                 119711          119707          1001            1001   0x0000000007a54000 2020-03-26 23:36:52 UTC+0000
```

Nous avons donc notre flag ! `FCSC{36280:fd:6663:7363:1000:55cf:b9c6:f41d:cc24:2020-03-26 23:24:20}`


<p align="center">
  <img src="./medias/evidence_meme.jpg">
</p>