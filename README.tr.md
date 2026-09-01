# toolwall

**Türkçe** · [English](README.md)

Ajanın özel verilerini okuyabiliyor. Ajanın açık interneti de okuyabiliyor.
`toolwall`, ikisini birden yapıp sonucu dışarı göndermesini engelleyen şey.

`toolwall`, MCP tool çağrıları için bir bilgi-akışı firewall'u: MCP client ile MCP
server arasına stdio üzerinden giren tek bir Go binary'si. Her oturumun neyi okuduğunu
takip eder ve o veriyi dışarı çıkaracak çağrıyı reddeder. Karar tamamen offline ve
deterministik: commit'lenmiş bir policy dosyasındaki etiketler, model yok, sınıflandırıcı
yok, servis çağrısı yok. Aynı çağrı dizisi her zaman aynı sonucu verir ve her ret, sebep
olan önceki çağrıyı ismiyle söyler.

[![Go Reference](https://pkg.go.dev/badge/github.com/YusufDrymz/toolwall.svg)](https://pkg.go.dev/github.com/YusufDrymz/toolwall)
[![CI](https://github.com/YusufDrymz/toolwall/actions/workflows/ci.yml/badge.svg)](https://github.com/YusufDrymz/toolwall/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Gateway'den üç çağrı geçiyor. Durum maili at: sorun yok. Özel notları oku: sorun yok.
Notlar oturuma girdikten sonra tekrar mail at:

```
$ toolwall run --server demo --audit audit.jsonl
toolwall: fronting "demo" in enforce mode
toolwall: denied send_email (exfiltration)

$ toolwall audit --file audit.jsonl
16:58:26 call       send_email(body, to)
16:58:26 call       read_notes()
16:58:26 DENIED     send_email
           rule exfiltration: sensitive data was read earlier in this scope
           because call 2 (read_notes) brought sensitive data in
16:58:26 result     send_email
16:58:26 result     read_notes

call         2
result       2
denied       1
```

Client'a gerçek bir JSON-RPC hatası dönüyor ve bu hata, onu okuyacak olan model için
yazılmış:

```
toolwall denied this call to "send_email": sensitive data was read earlier in this
scope. Call 2 (read_notes) brought sensitive data into this session. This is a policy
decision, not a transient failure: do not retry, and tell the user which rule blocked it.
```

Bu üç çağrının her biri tek başına masum. Saldırı olan şey sıralama, ve MCP yığınında
sıralamayı izleyen başka bir şey yok.

## Neden bu, neden diğer MCP güvenlik araçları değil

Gateway kategorisi kalabalık ve büyük kısmı başka bir problemi çözüyor:

| Araç | Ne yapıyor | Ne yapmıyor |
| --- | --- | --- |
| ToolHive, Docker MCP Gateway | sunucu sürecini izole ediyor: container, mount, network, imzalı imaj | çağrılar arasında verinin nereye gittiğine dair hiçbir şey |
| Pomerium, Kuadrant | kimlik: kim hangi sunucuya ve tool'a erişebilir, OAuth, rate limit | yetkili kullanıcının kendi ajanının kendi verisini sızdırması |
| Agent Scan (eski MCP-Scan) | tanımları poisoning ve shadowing için tarıyor | çağrı sırasına dair bir kuralı runtime'da uygulamak |

`toolwall` eksik olan parça: **çağrılar arası veri akışı**. Diğerlerinin yerine geçmiyor,
üstlerine biniyor. Sunucularını ToolHive içinde çalıştır, önüne Pomerium ile kimlik koy,
ve bu çağrının bu oturumda okunanlar ışığında dışarı çıkıp çıkamayacağına `toolwall`
karar versin.

## Kurulum

```sh
go install github.com/YusufDrymz/toolwall/cmd/toolwall@latest
```

Go 1.24+ gerekiyor. `CGO_ENABLED=0` ile derleniyor; test dışı tek bağımlılık
`gopkg.in/yaml.v3`.

Hazır binary'ler için [releases](https://github.com/YusufDrymz/toolwall/releases)
sayfasına bakabilirsin.

## Hızlı başlangıç

**1. Envanter çıkar.** `init`'i bir sunucuya doğrult; sunucunun neleri sunduğunu
listeler, etiketleri tahmin eder ve her tanımı pinler:

```sh
toolwall init --server demo -- go run ./examples/demo-server
```

```yaml
version: 1
mode: observe
servers:
    demo:
        command: go
        args:
            - run
            - ./examples/demo-server
tools:
    demo.read_notes:
        labels: [sensitive]
        digest: sha256:4b42ab67d786...
        note: 'suggested: looks like it reads private data (private)'
    demo.fetch_url:
        labels: [untrusted]
        digest: sha256:dbb68256376d...
    demo.send_email:
        labels: [sink]
        digest: sha256:26ac1cab73fd...
```

**2. Etiketleri düzelt.** Tahminler bir başlangıç noktası ve yeterince sık yanılıyorlar,
zaten dosya da bunu söylüyor. Üç etiket var ve her tool için soru kısa:

- `sensitive` : bu tool'u çağırmak oturuma özel veri sokuyor mu?
- `untrusted` : güven sınırının dışındaki birinin yazdığı içeriği getiriyor mu?
- `sink` : bu tool'u çağırmak veriyi dışarı gönderebilir mi?

Bir tool birden fazla etiket taşıyabilir. URL çeken bir tool genelde hem `untrusted` hem
`sink`'tir: sayfayı saldırgan kontrol ediyor, ve URL'in kendisi bir çıkış kapısı, çünkü
bildiğin her şey bir query string'e sığar.

**3. Duvarı öne koy.** MCP client konfigürasyonunda sunucu yerine `toolwall`'ı başlat:

```json
{
  "mcpServers": {
    "demo": {
      "command": "toolwall",
      "args": ["run", "--config", "/path/to/toolwall.yaml", "--server", "demo"]
    }
  }
}
```

`mode: observe` ile başla (her ihlal raporlanır, hiçbir şey engellenmez), bir gün boyunca
log'u oku, sonra `enforce`'a geç.

**4. CI'da dürüst tut.** `verify` her sunucuya yeniden bağlanıp, gözden geçirip
onayladığın bir tanımın altından değişip değişmediğini kontrol eder:

```sh
$ toolwall verify
[DRIFT] demo.read_notes definition changed since it was reviewed
        pinned sha256:4b42ab67d786...
        actual sha256:9f1c0a3e5521...

1 violation(s)
```

Rug pull dediğimiz şey bu: sunucu zararsız bir tool yayınlar, onaylanmasını bekler, sonra
açıklamayı talimat taşıyacak şekilde değiştirir. `verify` CI'da 1 ile çıkar. Runtime'da
ise gateway değişmiş tool'u `tools/list`'ten düşürür, böylece zehirli metin modele hiç
ulaşmaz, ve o tool'a yapılan çağrıları reddeder.

Bu ret, client'ın önce tool listesi çekmesine bağlı değil. Listeyi önceki oturumdan
cache'lemiş bir client hiç `tools/list` göndermez, ve birlikte gönderilen iki istek işine
yarayacak bir sırayla gelmez. Bu yüzden henüz doğrulanmamış pinli bir tool'a çağrı
geldiğinde gateway sunucudan tanımları kendisi ister ve cevabı bekler. Doğrulama
tamamlanamazsa çağrı geçirilmez, reddedilir: sadece zamanlama uygun olduğunda çalışan bir
pin, pin değildir.

## Birden çok sunucu, tek scope

`run` tek bir sunucunun önüne oturur. `serve` ise policy'deki tüm sunucuların önüne aynı
anda, tek bir paylaşılan akış scope'u ile oturur ve asıl mesele bu paylaşılan scope:

```sh
toolwall serve
```

Tool'lar policy'nin zaten kullandığı sunucu id'siyle öneklenir (`hr.read_record`,
`mail.send`). toolwall'ı client konfigürasyonuna bir kez koyarsın, hepsini toplar:

```json
{
  "mcpServers": {
    "toolwall": {
      "command": "toolwall",
      "args": ["serve", "--config", "/path/to/toolwall.yaml"]
    }
  }
}
```

Artık akış kuralları sunucular arasına uzanır. `hr` sunucusundan bir kayıt okuyup `mail`
sunucusundan dışarı göndermek, tek oturumda önce `sensitive` sonra `sink`'e dokunmaktır,
yani reddedilir. Sunucu-başına izolasyon ve kimlik gateway'lerinin göremediği geçiş tam
olarak budur, çünkü her birinin ayrı ayrı koruduğu iki sunucunun arasında olur.

Policy'yi sunucu sunucu `init --server` ile doldur; `verify` hepsini birden kontrol eder.

## Kurallar

Varsayılan policy iki kuraldan ibaret ve aracın var olma sebebi de bu iki kural:

```yaml
flow:
  deny:
    - name: exfiltration
      sink: [sink]
      after: [sensitive]
    - name: injection-exfiltration
      sink: [sink]
      after: [untrusted]
```

Şöyle oku: bu oturum `sensitive` (ya da `untrusted`) etiketli bir şeye dokunduysa,
`sink` etiketli hiçbir şeyi çağırma. `after` listesindeki etiketler AND'li, yani daha dar
olan versiyonu da yazabilirsin:

```yaml
flow:
  deny:
    - name: trifecta
      sink: [sink]
      after: [sensitive, untrusted]
      reason: tek oturumda özel veri, saldırgan kontrollü içerik ve bir çıkış kapısı
```

Etiketler serbest metin. Bir kuralın andığı her etiket kullanılabilir; hiçbir kuralın
anmadığı bir etiket ise yükleme anında hata verir. Sessizce bir tool'u sink olmaktan
çıkaran bir yazım hatası, tam olarak bu aracın engellemek için var olduğu şey.

Argümanlar da kısıtlanabilir, çoğu zaman tek başına bu bile yeterli olur:

```yaml
tools:
    demo.send_email:
        labels: [sink]
        args:
            to:
                allow: ['@yourcompany\.com$']
            body:
                max_len: 4096
```

## Ne yapmıyor

Bu bölüm özellik listesinden daha önemli.

- **Sandbox değil.** Kod çalıştıran bir tool, sürecin yapabildiği her şeyi yapabilir;
  `toolwall` JSON-RPC görür, syscall görmez. İzolasyon için ToolHive ya da Docker
  gateway'ini kullan, `toolwall`'ı onun içine koy.
- **Tool'larını senin yerine etiketleyemez.** `init` içindeki sezgisel tahminler sadece
  taslak yardımcısı. Yanlış etiketlenmiş bir gateway, hiç olmamasından kötüdür, çünkü
  koruma varmış hissi verir.
- **Tek bir çağrı da sızdırma olabilir.** Bir tool hem özel veri okuyup hem ağa
  erişiyorsa hiçbir sıralama kuralı işe yaramaz. Böylelerini baştan `sink` etiketle ve
  argümanlarını kısıtla.
- **Scope, gateway sürecidir.** `run` ve `serve` için de bir toolwall süreci bir akış
  scope'udur; `serve` bunu önündeki tüm sunucular arasında paylaşır, ki özellik de bu.
  2026-07-28 revizyonu bir bağlantının oturum olmadığını açıkça söylüyor ve bir proxy'ye
  konuşma kimliği vermiyor; client'ın `_meta` içinde bir korelasyon id'si set ediyorsa
  `--scope-key` ile onu göster, akış konuşma başına izlensin.
- **`serve` tool ve prompt'ları proxy'ler.** Resource'lar henüz toplanmıyor; onlara
  ihtiyacı olan bir client o sunucuya doğrudan bağlanmalı.
- **Şimdilik sadece stdio.** Uzak sunucular Streamable HTTP'de ve sıradaki iş o.
- **Model hâlâ konuşabilir.** `toolwall` tool çağrılarını korur, modelin kullanıcıya
  verdiği cevapları okumaz.

## Protokol desteği

Konfigürasyon gerekmeden iki era da destekleniyor. 2026-07-28 revizyonu `initialize`
handshake'ini kaldırdı ve her isteği kendi kendine yeter hale getirdi; 2025-11-25 ve
öncesi ise oturum istiyor. `init` ve `verify`, spec'in stdio geri uyumluluk kurallarında
tarif edildiği gibi önce `server/discover` ile yokluyor, olmazsa `initialize`'a düşüyor.
Gateway'in kendisi hiçbirini yeniden yazmıyor: client ne gönderiyorsa sunucu onu görüyor,
yani modern bir client ile legacy bir sunucu aralarındaki düzeni korumaya devam ediyor.

## Geliştirme

```sh
go test -race -cover ./...
```

Testler scriptlenebilir sahte bir sunucuyu (`internal/fakemcp`) child process olarak
çalıştırıyor. Böylece zor durumlar, yani legacy bir sunucu, `_meta` olmadan gelen isteği
reddeden bir sunucu, iki listeleme arasında tool açıklamasını değiştiren bir sunucu ve
duvarı yarışa sokmak için iki çağrıyı birlikte gönderen bir client, ağa hiç dokunmadan
kapsanıyor.

## Lisans

MIT
