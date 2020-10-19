---
layout: post
title: Stored Credentials and Unattended Install Files
description: "Kayıtlı hesap bilgileri ile sistemde yetki yükseltme."
modified: 2020-08-16
comments: true
categories: TR
tags: [yetki yükseltme, privilege escalation, windows, pentest]
---

## Özet

Kötü niyetli kişi makineye düşük ayrıcalıklarla erişim sağladığında ayrıcalıklarını artırmak için sistem içerisinde düz yazı olarak kayıt edilmiş kullanıcı bilgileri arar. Ayrıcalıkları artırmanın en kolay ve fark edilmesi zor olan bir yoldur.  Bu dosyaların bulunabileceği belli başlı birkaç yer vardır. 

## Windows

### Unattend files

Sistem yöneticileri defalarca kez Windows kurup ayarlarını yapmak yerine bu işi otomatikleştirmeyi tercih ederler. Windows bunun için unattend (katılımsız kurulum) kurulumu özelliğini sağlar. Sistem yöneticisi kurulumda yapmak istediği tüm ayarları bir xml dosyası olarak hazırlar. Bu dosyaya cevap dosyası (answer files) adı verilir. Bu dosyanın içerisine yerel yönetici (local admin) kullanıcısının parolası düz metin olarak ya da base64 ile encode edilerek yazılır. Bu dosyaları;

~~~
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
~~~
bulabilirsiniz. 

Bir unattend dosyası okunduğunda içerisinde <Password> etiketi olup olmadığı araştırılmalı.

```xml
<UserAccounts>
	<LocalAccounts>
        	<LocalAccount>
            		<Password>
               			 <Value>UEBzc3dvcmQxMjMhUGFzc3dvcmQ= </Value>
                		<PlainText>false</PlainText>
            		</Password>
            		<Description>Local Administrator</Description>
            		<DisplayName>Administrator</DisplayName>
            		<Group>Administrators</Group>
            		<Name>Administrator</Name>
        	</LocalAccount>
 	</LocalAccounts>
</UserAccounts>
```

İlgili etiket kontrol edildiğinde Administrator parolasının “UEBzc3dvcmQxMjMhUGFzc3dvcmQ=” olduğu görünüyor. \<PlainText\> etiketi kontrol edilirse parolanın düz metin olarak saklanmadığı gösterilmiş. Değeri base64 ile decode ederek “P@ssword123!Password” elde ederiz. Windows burada parolanın sonuna “Password” ekliyor. Bunu silerek gerçek parola elde edilebilir.

#### Group Policy Preferences

Sistem yöneticileri bazen benzer çözümler için yerel yöneticilerin (local admin) parolalarını Group Policy içine kayıt ederek Policy’i yayınlar. Parolayı içeren Groups.xml dosyası yerel olarak önbelleğe alınır veya her etki alanı kullanıcısının bu dosyaya okuma erişimi olduğu için etki alanı denetleyicisinden alınabilir. Buradaki parola şifrelenmiş şekilde bulunur ancak Microsoft şifrelemede kullanılan anahtarı yanlışlıkla(?) herkese açık şekilde yayınlamıştır. Elde edilen şifrelenmiş parola “gpp-decrypt” ile çözülebilir. Bulunabileceği yerler;

~~~
C:\ProgramData\Microsoft\Group Policy\History\????\Machine\Preferences\Groups\Groups.xml
\\????\SYSVOL\\Policies\????\MACHINE\Preferences\Groups\Groups.xml
~~~

İçerisinde aynı şekilde şifrelenmiş parola bulabileceğiniz diğer dosyalar;

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

#### Web.config

Bir başka yol olarak web.config dosyaları aranabilir. Bu dosyaların içleri kontrol edildiğinde parola bulma ihtimaliniz vardır.

~~~
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
~~~

```xml
<authentication mode="Forms"> 
  <forms name="login" loginUrl="/admin">
    <credentials passwordFormat = "Clear">
      <user name="Administrator" password="P@ssword123!" />
        </credentials>
  </forms>
</authentication>
```

#### Credential Manager

Windows, izin verdiğiniz bilgileri Kimlik Bilgileri Yöneticisinde tutar.

<p align="center">
	<img src="/images/stored_credentials_ss/1.png" alt="">
</p>

#### Windows Autologin

Windows otomatik login özelliği aktifleştirilmiş ise kayıt defterinde parola bulabilirsiniz.

~~~
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
~~~

### Üçüncü Parti Uygulamalar

#### McAfee

~~~
%AllUsersProfile%Application Data\McAfee\Common Framework\SiteList.xml
~~~

#### VNC

~~~
[ultravnc]
passwd=5FAEBBD0EF0A2413
~~~

#### RealVNC

Parolasını kayıt defterinde tutar.

~~~
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
~~~

#### Putty

Parolasını kayıt defterinde tutar.

~~~
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
~~~

## Bulma Yöntemleri

### Yol -1:

Manuel olarak komut satırına aşağıda ki komutları ve benzerlerini girerek bulabilirsiniz.

~~~
dir c:\*vnc.ini /s /b /c
dir c:\*ultravnc.ini /s /b /c
dir c:\ /s /b /c | findstr /si *vnc.ini
dir /b /s *pass*
dir /b /s unattend.xml
dir /b /s web.config
dir /b /s sysprep.inf
dir /b /s sysprep.xml
findstr /si password *.txt | *.xml | *.ini
findstr /si pass *.txt | *.xml | *.ini
~~~

### Yol -2:

<a href="https://github.com/hlldz/dazzleUP">DazzleUP</a> kullanarak bu dosyaları otomatik olarak tespit edebilirsiniz.

<p align="center">
	<img src="/images/stored_credentials_ss/2.png" alt="" >
</p>

### Yol -3: 

<a href="https://github.com/AlessandroZ/LaZagne">LaZagne</a> kullanarak kayıtlı parolaları bulabilirsiniz.

<p align="center">
	<img src="/images/stored_credentials_ss/3.png" alt="" >
</p>

## Kaynakça:

* https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/update-windows-settings-and-scripts-create-your-own-answer-file-sxs#:~:text=Answer%20files%20(or%20Unattend%20files,and%20picks%20their%20default%20language.
* https://pentestlab.blog/2017/04/19/stored-credentials/
* https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview#implicit-answer-file-search-order
* https://github.com/AlessandroZ/LaZagne
* https://github.com/hlldz/dazzleUP
