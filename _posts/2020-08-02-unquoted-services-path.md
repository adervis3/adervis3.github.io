---
layout: post
title: Unquoted Services Path
description: "Yanlış yapılandırılmış servis yolu zafiyeti."
modified: 2020-08-02
comments: true
categories: TR
tags: [yetki yükseltme, privilege escalation, windows, pentest]
---

## Özet

Yanlış Servis Yolu Yapılandırması, (Unquoted Services Path) Windows işletim sistemlerinde hak yükseltmek için kullanılan ve oldukça fazla karşılaşılan bir yöntemdir. Zafiyetin temelinde Windows'un, servisin çalıştırılabilir dosyasını bulmak için kullandığı yöntem vardır. İstismar edilerek yerel sistemde yetki yükseltilebilir.

## Detaylar

Windows işletim sistemlerinde bir servis çalıştırıldığında, işletim sistemi servisi başlatmak için ilgili çalıştırılabilir dosyayı bulması gerekir. Örneğin Fax servisinin başlaması için işletim sisteminin **“C:\Windows\system32\”** yolundaki **"fxssvc.exe"** yürütülebilir dosyayı bilmesi gerekir. Dosya yolu “” içine eklenmiş ise işletim sistemi bu dosyanın tam olarak nerede olacağını bilecektir. Eğer “” içine eklenmemiş direkt

```
C:\Windows\system32\fxssvc.exe
```
şeklinde ilgili çalıştırılabilir dosyayı bulacaktır. 

<p align="center">
	<img src="/images/unquoted_ss/1.png" alt="">
</p>

Çalıştırılacak dosya yolu içerisinde boşluk var ve “” içerisine alınmamış ise işletim sistemi dosyanın tam olarak nerede olduğunu bilemeyecek ve aramayı sırası ile;

```
C:\Program.exe
C:\Program Files.exe
C:\Program Files (x86).exe
C:\Program Files (x86)\Lavasoft.exe
C:\Program Files (x86)\Lavasoft\Web.exe
C:\Program Files (x86)\Lavasoft\Web Companion.exe
C:\Program Files (x86)\Lavasoft\Web Companion\Application.exe
C:\Program Files (x86)\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe
```

şeklinde yaparak ilgili dosyayı arayacaktır. Özetle işletim sistemi bu dosyayı buluncaya kadar ilgili yoldaki her dosyanın sonuna .exe ekleyerek tek tek çalıştırılabilir dosyayı arayacaktır. 

### Zafiyetin Kaynağı

İşletim sisteminin bu şekilde davranmasındaki sebep **CreateProcess** çağrısındaki **lpApplicationName** parametresidir. lpApplicationName parametresi çalıştırılacak modülün tam yolu ve dosya adı olmalıdır. Aksi taktirde işletim sistemi çalıştırılabilir dosyayı aramaya başlayacaktır.

> The lpApplicationName parameter can be NULL. In that case, the module name must be the first white space–delimited token in the lpCommandLine string. If you are using a long file name that contains a space, use quoted strings to indicate where the file name ends and the arguments begin; otherwise, the file name is ambiguous. For example, consider the string "c:\program files\sub dir\program name". This string can be interpreted in a number of ways. The system tries to interpret the possibilities in the following order:
c:\program.exe c:\program files\sub.exe c:\program files\sub dir\program.exe c:\program files\sub dir\program name.exe If the executable module is a 16-bit application, lpApplicationName should be NULL, and the string pointed to by lpCommandLine should specify the executable module as well as its arguments.

<a href="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa#parameters">Kaynak</a>


<p align="center">
	<img src="/images/unquoted_ss/2.png" alt="">
</p>

### İstismar Edilmesi

Bu durumda zararlı yazılım hazırlanıp kök dizinden başlayacak şekilde yazma izni olan herhangi bir yola yerleştirilirse servis tekrar başlatıldığında zararlı yazılım çalışacaktır. Örneğin “C:\” dizinine Program.exe isminde yerleştirilen herhangi bir yürütülebilir dosya çalışacaktır. 

Program.exe adında ki zararlı yazılımın oluşturulmasına dair ekran görüntüsü verilmiştir.

<p align="center">
	<img src="/images/unquoted_ss/3.png" alt="">
</p>

Zararlı yazılımın sisteme yüklendiğine ve zafiyeti barındıran yollardan birisine koyulduğuna dair ekran görüntüsü verilmiştir.

<p align="center">
	<img src="/images/unquoted_ss/4.png" alt="">
</p>

Çalıştırılan zararlı, servisin çalıştırıldığı haklar ile aynı haklarda çalışacaktır.

<p align="center">
	<img src="/images/unquoted_ss/5.png" alt="" >
</p>

Yapılandırma eksikliği olan servisin çalıştırıldıktan sonra zararlı yazılımı tetiklemesi ile NT AUTHORITY\SYSTEM haklarında elde edilen meterpreter oturumunun ekran görüntüsü verilmiştir.

<p align="center">
	<img src="/images/unquoted_ss/6.png" alt="" >
</p>

### NOT

Windows işletim sistemi servisin düzgün başlatılıp başlatılmadığını kontrol eder. Eğer servis 3 dakika içerisinde düzgün başlatılmaz ise aşağıda ki ekran görüntüsünde verilen bilgilendirmeyi yapar ve öncesinde başlattığı bütün süreçleri öldürür. Manipüle edilen servis düzgün başlatılmadığı için bu yapılandırma eksikliğinde aynı problemle karşılaşabilirsiniz. Kısa süre içerisinde başka bir sürece migrate olmanız gerekmektedir.

<p align="center">
	<img src="/images/unquoted_ss/7.png" alt="" >
</p>

## Servislerin Bulunması

### Yol -1:

Manuel olarak komut satırında 

```
wmic service get name,displayname,pathname,startmode |findstr /i “auto” |findstr /i /v “c:\windows\\” |findstr /i /v “””
```

komutu yeterli olacaktır.

<p align="center">
	<img src="/images/unquoted_ss/8.png" alt="" >
</p>


### Yol -2:

<a href="https://github.com/hlldz/dazzleUP">DazzleUP</a> kullanarak yanlış yapılandırılmış servis yollarını tespit edebilirsiniz.

<p align="center">
	<img src="/images/unquoted_ss/9.png" alt="">
</p>


### Yol -3:

PowerUp.ps1 kullanarak **Get-ServiceUnquoted** fonksiyonu ile bulunabilir.

<p align="center">
	<img src="/images/unquoted_ss/10.png" alt="">
</p>


## Çözüm:

Kayıt defterindeki **HKLM\SYSTEM\CurrentControlSet\services** bölümü incelenir. Servislerden ImagePath dizesi kontrol edilir. Dikkat edilmesi gereken nokta çift tırnak içinde olmayan ve içinde boşluk geçen yollardır.

<p align="center">
	<img src="/images/unquoted_ss/11.png" alt="">
</p>

ImagePath dizesi düzenlenerek yol çift tırnak içine alınır ve ilgili yapılandırma eksikliği giderilmiş olur.

<p align="center">
	<img src="/images/unquoted_ss/12.png" alt="">
</p>


## Kaynakça:

* https://support.microsoft.com/tr-tr/help/278712/error-message-error-1053-when-using-the-services-snap-in
* https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa#parameters
* https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341
* https://github.com/hlldz/dazzleUP
