---
layout: post
title: Always Install Elevated
description: "AlwaysInstallElevated özelliği aktif makinede yetki yükseltme."
modified: 2020-08-10
comments: true
categories: TR
tags: [yetki yükseltme, privilege escalation, windows, pentest]
---

## Özet

AlwaysInstallElevated, Windows işletim sistemlerinde yüksek ayrıcalıklarla MSI paketlerini çalıştırmaya izin veren bir özelliktir. Kötü niyetli kişiler tarafından istismar edilerek NT AUTHORITY\SYSTEM ayrıcalıkları elde edilebilir. 

## Detaylar

Windows işletim sistemi uygulamaları yüklemek için MSI (Microsoft Windows Installer) paketlerini kullanır. AlwaysInstallElevated özelliği aktif ise Windows, MSI paketlerini normal kullanıcılar için sistem ayrıcalıklarında yüklemesine izin verir. Burada ki amaç kullanıcıların sistem ayrıcalıkları gerektiren bir uygulama yüklemek istediğinde sistem yöneticisinin kullanıcıya geçici yerel yönetici erişimi vermeden kurulum yapabilmesini sağlamaktır. Ancak kötü niyetli kişiler tarafından bu durum istismar edilerek NT AUTHORITY\SYSTEM ayrıcalıklarına yükselmek için kullanılabilir. İstismar edildiğinde sistemde çok fazla ayrıcalık elde edilebileceği için bu özelliğin kullanılmaması tavsiye edilmektedir. Kısacası AlwaysInstallElevated bir zafiyet değildir, özelliğin kötüye kullanımı sayesinde hak yükseltilebilmesini sağlar.

**NOT:** MSI paketlerinin çalışması için yüksek ayrıcalıklara ihtiyaçları yoktur. 

> This policy setting directs Windows Installer to use elevated permissions when it installs any program on the system.
If you enable this policy setting, privileges are extended to all programs. These privileges are usually reserved for programs that have been assigned to the user (offered on the desktop), assigned to the computer (installed automatically), or made available in Add or Remove Programs in Control Panel. This profile setting lets users install programs that require access to directories that the user might not have permission to view or change, including directories on highly restricted computers
If you disable or do not configure this policy setting, the system applies the current user's permissions when it installs programs that a system administrator does not distribute or offer.
Note: This policy setting appears both in the Computer Configuration and User Configuration folders. To make this policy setting effective, you must enable it in both folders.
Caution: Skilled users can take advantage of the permissions this policy setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this policy setting is not guaranteed to be secure.

**Kaynak:** Group Policy “Always install with elevated privileges” Settings

Zafiyetin kaynağı aşağıda verilmiş olan anahtar kısmına DWORD tipinde “AlwaysInstallElevated“ değeri 1 olarak ayarlanmış olmasıdır. 

~~~
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
~~~

2 farklı yol ile aşağıda gösterilmiştir.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/1.png" alt="">
</p>

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/2.png" alt="">
</p>

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/3.png" alt="">
</p>


## İstismar Edilmesi

### Yol -1:

Senaryo olarak hedef sistemde test adlı düşük ayrıcalıklardaki kullanıcının Program.msi dosyasını indirip kurması beklenmektedir. 

İlk adımda msfvenom ile reverse_tcp üzerinden meterpreter oturumu oluşturacak zararlı yazılımımızı hazırlıyoruz. Daha sonra zararlı yazılımı NT AUTHORITY\SYSTEM ayrıcalıklarında çalıştıracak yükseliyici scriptimizi (msi) hazırlıyoruz. Scripte zararlının hangi dizinde olacağını bildiriyoruz.
Zararlı yazılımın ve yükleyici scriptin oluşturulmasına ait ekran görüntüsü aşağıda verilmiştir. 

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/4.png" alt="">
</p>

Yükleyici scriptin çalıştırılıp zararlı yazılımı tetiklemesine dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/5.png" alt="">
</p>

Yükleyici script çalıştıktan sonra zararlı yazılım tetiklendi ve meterpreter oturumu elde edildi. Elde edilen meterpreter oturumu aşağıda verilmiştir.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/6.png" alt="">
</p>

### Yol -2:

Bir farklı senaryo olarak direkt olarak meterpreter oturumu elde edilerek sisteme erişilmesi gösterilmiştir.

İlk adımda msfvenom ile reverse_tcp üzerinden meterpreter oturumu oluşturacak yükleyici scripti hazırlıyoruz. Script NT AUTHORITY\SYSTEM ayrıcalıklarında çalışacağı için meterpreter oturumuda NT AUTHORITY\SYSTEM ayrıcalıklarında olacaktır. İkinci bir zararlı yazılıma ihtiyaç duyulmayacaktır. 

**NOT:** Bu durum incelendiğinde msfvenom ile script üretilirken payload olarak windows/exec seçilerek komutta çalıştırabilirsiniz. Ancak bu durum hak yükseltme olmadığı için bu yazının konusu değildir.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/7.png" alt="">
</p>

Zararlı scriptin çalıştırılarak meterpreter oturumunu açtığına dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/8.png" alt="">
</p>

NT AUTHORITY\SYSTEM ayrıcalıklarında elde edilen meterpreter oturumu aşağıda gösterilmiştir.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/9.png" alt="">
</p>

### Yol -3:

Son senaryo olarak sisteme düşük ayrıcalıklarda bulaşmış bir zararlı yazılım olsun. Zararlı yazılımdan meterpreter oturumu elde edilmiş olsun. Eğer ki ilgili zafiyet varsa sisteme yine bir yükleyici script oluşturarak NT AUTHORITY\SYSTEM ayrıcalıklarına erişilebilir.

Sistemde düşük ayrıcalıklara sahip kullanıcı üzerinden oluşturulmuş meterpreter oturumu aşağıda gösterilmiştir. 

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/12.png" alt="">
</p>

Oturum arka plana atılarak metasploitte ki always_install_elevated modülü çalıştırılarak yüksek ayrıcalıklara geçilecek. Gerekli ayarların yapılıp modülün çalıştırılması ve NT AUTHORITY\SYSTEM ayrıcalıklarına geçiş aşağıda gösterilmiştir.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/13.png" alt="">
</p>

## Bulma Yöntemleri

### Yol -1:

Manuel olarak komut satırında

~~~
reg query HKLM\Software\Policies\Miscrosoft\Windows\Installer
reg query HKCU\Software\Policies\Miscrosoft\Windows\Installer
~~~

komutları girildikten sonra AlwaysInstallElevated 0x1 olarak belirlenmiş olmalıdır.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/10.png" alt="">
</p>


### Yol -2:

<a href="https://github.com/hlldz/dazzleUP">DazzleUP</a> kullanarak yüksek ayrıcalıklarda yükleme yapılandırma zafiyetini tespit edebilirsiniz.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/11.png" alt="">
</p>

## Çözüm

Kayıt defteri açılarak (regedit) aşağıda verilmiş anahtarlar içerisinden AlwaysInstallElevated değeri 0 olarak düzenlenmelidir.

~~~
HKLM\Software\Policies\Miscrosoft\Windows\Installer
HKCU\Software\Policies\Miscrosoft\Windows\Installer
~~~

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/14.png" alt="">
</p>

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/15.png" alt="">
</p>

Eğer özellik group policy ile aktif edilmiş ise policynin disable olması gereklidir. İlgili ayar için gpedit -> Computer Configuration -> Administrative Templates -> All Settings -> Always install with elevated privileges

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/16.png" alt="">
</p>

Gerekli düzenlemelerden sonra zafiyet tekrar araştırılarak ilgili zafiyetin olmadığına dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/17.png" alt="">
</p>

<p align="center">
	<img src="/images/alwaysinstallelevated_ss/18.png" alt="">
</p>

## Kaynakça

*	https://docs.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated
*	https://github.com/hlldz/dazzleUP
*	https://dmcxblue.gitbook.io/red-team-notes/privesc/unquoted-service-path

