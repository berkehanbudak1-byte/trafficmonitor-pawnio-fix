# TrafficMonitor – remplacer WinRing0 par PawnIO

🇫🇷 Français · [🇬🇧 English below](#english)

**TrafficMonitor 1.86** (la dernière version à ce jour) affiche les températures grâce à
LibreHardwareMonitorLib **0.9.4**. Cette bibliothèque installe en arrière-plan le pilote noyau
**WinRing0**, qui a une faille de sécurité connue (**CVE-2020-14979**).
Ce dépôt propose des scripts pour remplacer cette bibliothèque par la version officielle **0.9.6**,
qui passe par le pilote moderne **PawnIO** à la place. On garde ainsi l'affichage des températures,
sans WinRing0.

> ⚠️ Ce correctif n'est pas officiel. Il n'est ni fait ni approuvé par le développeur de TrafficMonitor
> ou de LibreHardwareMonitor. Tu l'utilises à tes propres risques. Un script de retour arrière est fourni.

---

## 1. Le problème

### Ce qui se passe
Quand l'affichage des températures (CPU, GPU, disque ou carte mère) est activé, TrafficMonitor fait trois choses à chaque démarrage :

1. il écrit un fichier `TrafficMonitor.sys` dans son dossier d'installation ;
2. il l'enregistre comme service de pilote noyau sous le nom **`R0TrafficMonitor`** ;
3. il le démarre.

Ce fichier `.sys` est en réalité **WinRing0 1.2.0.5**, signé par Noriyuki Miyazaki (CrystalMark).
Ce pilote est connu pour sa vulnérabilité **CVE-2020-14979**, notée **7,8/10 (élevée)**.

### La faille
WinRing0 sert normalement à lire les capteurs. Pour ça, il donne un accès direct au matériel :
la **mémoire physique**, les **ports d'entrée-sortie** et les **registres internes du processeur (MSR)**.
Le problème, c'est que **n'importe quel programme peut s'en servir, même sans droits administrateur** :
le pilote ne vérifie pas qui l'appelle.

### Ce que ça expose
Un programme malveillant qui tourne déjà sur le PC, même avec des droits limités,
peut utiliser ce pilote pour :

- **lire et écrire dans la mémoire du noyau**, et donc obtenir les droits SYSTEM (élévation de privilèges) ;
- **désactiver ou aveugler l'antivirus ou l'EDR** ;
- s'installer en profondeur dans le système, comme un rootkit.

L'intégrité de la mémoire (HVCI) empêche d'exécuter du code non signé dans le noyau, mais elle
**n'empêche pas de modifier des données** dans la mémoire du noyau, par exemple pour voler le jeton SYSTEM.
D'après nos constats, la liste de blocage des pilotes vulnérables de Microsoft ne bloque pas non plus cette version.

### Quel est le risque réel ?
| Question | Réponse |
|---|---|
| Exploitable à distance ? | **Non.** Il faut qu'un programme malveillant tourne **déjà** sur la machine |
| Quand le PC est-il exposé ? | **Tant que TrafficMonitor tourne avec l'affichage des températures activé**, car c'est là que le pilote est chargé |
| Gravité si c'est exploité | **Élevée** : une infection banale devient une prise de contrôle totale du système, invisible pour l'antivirus |
| Mise à jour officielle ? | **Aucune** à ce jour : la version 1.86 embarque toujours LibreHardwareMonitorLib 0.9.4 |

Microsoft Defender signale d'ailleurs ce pilote sous le nom `VulnerableDriver:WinNT/Winring0`.

### Comment le vérifier sur ton PC
```powershell
sc.exe query R0TrafficMonitor                                   # service WinRing0 présent ?
Get-Item "C:\Program Files\TrafficMonitor\TrafficMonitor.sys"   # pilote déposé ?
(Get-Item "C:\Program Files\TrafficMonitor\LibreHardwareMonitorLib.dll").VersionInfo.FileVersion   # 0.9.4.0 = concerné
```

---

## 2. La solution

À partir des versions 0.9.5 et 0.9.6, LibreHardwareMonitorLib **n'utilise plus WinRing0**. Il passe par
**[PawnIO](https://github.com/namazso/PawnIO.Setup)**, un pilote signé par Microsoft (WHCP) et conçu pour
ne donner qu'un accès limité et contrôlé au matériel.

Ce qui rend le remplacement possible :

- TrafficMonitor charge LibreHardwareMonitorLib à travers son propre module `OpenHardwareMonitorApi.dll`.
- La bibliothèque n'a pas de signature à nom fort (strong name). .NET charge donc la nouvelle version sans exiger le même numéro de version.
- **Les fonctions que TrafficMonitor utilise sont identiques** entre 0.9.4 et 0.9.6.
  On l'a vérifié par réflexion .NET : `Computer`, `IVisitor`, `IHardware`, `ISensor`, et les valeurs des types de matériel et de capteurs utilisés.
- Un seul type de capteur (`Timing`) a été ajouté en 0.9.6. Il décale les valeurs à partir de 16 (`Energy`, `Noise`, etc.),
  mais TrafficMonitor n'utilise que `Clock`, `Load` et `Temperature`, dont les valeurs ne changent pas.

### Ce que fait `install.ps1`
1. Il vérifie que PawnIO est installé et que TrafficMonitor est bien en 64 bits (x64).
2. Il télécharge **depuis nuget.org** LibreHardwareMonitorLib 0.9.6 et toutes les bibliothèques dont elle a besoin pour .NET Framework 4.7.2 (14 paquets).
3. Il vérifie que **chaque paquet est identique au bit près** à celui publié officiellement (comparaison avec l'empreinte SHA-512 du catalogue NuGet).
4. Il confirme que la nouvelle bibliothèque fait référence à PawnIO et plus du tout à WinRing0.
5. Il compare les fonctions utilisées par TrafficMonitor entre l'ancienne et la nouvelle version, et **s'arrête à la moindre différence**.
6. Il sauvegarde l'ancienne version dans un dossier `_backup_lhm_<date>` à l'intérieur du dossier de TrafficMonitor.
7. Il ferme TrafficMonitor proprement, ce qui conserve l'historique de trafic.
8. Il **supprime le service `R0TrafficMonitor` et le fichier `TrafficMonitor.sys`**.
9. Il copie les 13 nouvelles DLL et relance TrafficMonitor.

Ce dépôt ne contient aucun fichier binaire : tout est téléchargé depuis nuget.org.

---

## 3. Utilisation

### Prérequis
- Windows 10 ou 11 en 64 bits, avec TrafficMonitor **1.86** installé (testé avec cette version).
- **PawnIO** installé :
  ```powershell
  winget install --id namazso.PawnIO -e
  ```
  Tu peux aussi le télécharger depuis <https://github.com/namazso/PawnIO.Setup/releases>.

### Simulation (ne modifie rien, pas besoin des droits administrateur)
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -DryRun
```

### Installation (dans PowerShell lancé **en administrateur**)
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

### Vérification (en administrateur pour lire les capteurs)
```powershell
powershell -ExecutionPolicy Bypass -File .\verify.ps1
```
Exemple de résultat :
```
[OK] LibreHardwareMonitorLib 0.9.6.0 does not embed WinRing0
[OK] No WinRing0 service (R0TrafficMonitor)
[OK] No WinRing0 driver file (TrafficMonitor.sys)
[OK] PawnIO driver installed (Running)
[OK] CPU temperature read through PawnIO:
       Cpu | 12th Gen Intel Core i7-12700H | CPU Package = 63.0 C
       GpuNvidia | NVIDIA GeForce RTX 3080 Ti Laptop GPU | GPU Core = 58.0 C
```

Options supplémentaires de `verify.ps1` :
- `-Json` : émet un rapport structuré JSON (pour le monitoring automatisé).
- `-SelfTest` : teste la détection WinRing0 hors ligne (sans droits administrateur).
- `-ExportReport <chemin>` : exporte une fiche de santé diagnostique en HTML (`.html`) ou Markdown (`.md`).

```powershell
powershell -ExecutionPolicy Bypass -File .\verify.ps1 -Json
powershell -ExecutionPolicy Bypass -File .\verify.ps1 -SelfTest
powershell -ExecutionPolicy Bypass -File .\verify.ps1 -ExportReport .\health-card.html
```

### Retour arrière
```powershell
powershell -ExecutionPolicy Bypass -File .\rollback.ps1
```
⚠️ Le retour arrière remet l'ancienne bibliothèque, et donc **WinRing0 et sa faille**.

---

## 4. À savoir

- **Une mise à jour de TrafficMonitor remet la bibliothèque 0.9.4**, et donc WinRing0.
  Après chaque mise à jour, relance `verify.ps1`, puis `install.ps1` si besoin.
- **Autre solution sans rien remplacer** : désactive tous les éléments de « surveillance matérielle »
  dans les options de TrafficMonitor. WinRing0 n'est alors plus chargé, mais tu perds l'affichage des températures.
- **Testé sur** : Windows 11, TrafficMonitor 1.86 en x64, Intel Core i7 de 12e génération, NVIDIA RTX série 30, SSD NVMe,
  PawnIO 2.2.0. Températures du CPU, du GPU et des SSD lues correctement, aucun échec de chargement .NET.
- Le correctif idéal serait que TrafficMonitor intègre lui-même une version récente de LibreHardwareMonitorLib.

## Références
- [CVE-2020-14979 – SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2020-14979/)
- [CVE-2020-14979 – cvefeed](https://cvefeed.io/vuln/detail/CVE-2020-14979)
- [Microsoft – alerte VulnerableDriver:WinNT/Winring0](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/microsoft-defender-antivirus-alert-vulnerabledriver-winnt-winring0)
- [TrafficMonitor – versions publiées](https://github.com/zhongyang219/TrafficMonitor/releases)
- [LibreHardwareMonitor – versions publiées](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases)
- [LibreHardwareMonitorLib sur NuGet](https://www.nuget.org/packages/LibreHardwareMonitorLib)
- [PawnIO.Setup](https://github.com/namazso/PawnIO.Setup)

---

<a id="english"></a>
## 🇬🇧 English

**Problem.** When hardware monitoring is enabled, TrafficMonitor 1.86 (latest release) uses the bundled
LibreHardwareMonitorLib **0.9.4**. On every start, that library drops `TrafficMonitor.sys` next to the executable
and loads it as the kernel driver service `R0TrafficMonitor`. The file is **WinRing0 1.2.0.5**, affected by
**CVE-2020-14979** (CVSS 7.8). Any process, even unprivileged, can use it to read and write physical memory, I/O ports
and MSRs. That means local privilege escalation to SYSTEM and the ability to tamper with AV/EDR (a classic
"bring your own vulnerable driver" attack). It is not remotely exploitable, but it turns any local foothold
into full kernel control while TrafficMonitor is running. No upstream fix exists yet.

**Fix.** LibreHardwareMonitorLib 0.9.5+ uses the Microsoft-signed **PawnIO** driver instead of WinRing0.
The public API that TrafficMonitor's `OpenHardwareMonitorApi.dll` uses is identical between 0.9.4 and 0.9.6
(verified by reflection). The only enum change is `SensorType.Timing`, inserted at value 16, which does not affect
the `Clock`, `Load` and `Temperature` sensor types TrafficMonitor reads. The library is not strong-named, so it can be
swapped in place.

**Usage** (requires PawnIO: `winget install --id namazso.PawnIO -e`):

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -DryRun   # download + verify only
powershell -ExecutionPolicy Bypass -File .\install.ps1           # elevated: backup, remove WinRing0, install
powershell -ExecutionPolicy Bypass -File .\verify.ps1            # elevated: full check incl. sensor read
powershell -ExecutionPolicy Bypass -File .\verify.ps1 -Json      # structured JSON diagnostics
powershell -ExecutionPolicy Bypass -File .\verify.ps1 -SelfTest  # offline WinRing0 detection self-test
powershell -ExecutionPolicy Bypass -File .\verify.ps1 -ExportReport .\health-card.html  # HTML (.html) or Markdown (.md) health card
powershell -ExecutionPolicy Bypass -File .\rollback.ps1          # elevated: restore original (re-enables WinRing0)
```

`install.ps1` downloads LibreHardwareMonitorLib 0.9.6 and its .NET Framework 4.7.2 dependency tree from nuget.org.
It verifies each package against the nuget.org catalog SHA-512, checks for PawnIO references and no WinRing0, and
compares the API. It then backs up the original, gracefully closes TrafficMonitor, deletes the `R0TrafficMonitor`
service and `TrafficMonitor.sys`, installs the 13 DLLs and restarts TrafficMonitor.
No binaries are stored in this repository.

A TrafficMonitor update will restore the vulnerable library: re-run `verify.ps1` / `install.ps1` after updating.
This fix is unofficial and you use it at your own risk.

## License
Scripts: MIT (see `LICENSE`). LibreHardwareMonitorLib is MPL-2.0 and is downloaded from nuget.org, not redistributed here.
