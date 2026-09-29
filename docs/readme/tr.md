# trustdiff

[English README](../../README.md) | Türkçe

![Ceviri guncelligi](https://github.com/vahapogut/trustdiff/actions/workflows/readme-translations.yml/badge.svg)

trustdiff, bir projenin bağımlılıklarında güvenin zayıfladığını gösteren
değişiklikleri inceleyen bir komut satırı aracıdır. Yeni bir yayıncı, kaybolan
kaynak doğrulama bilgisi, eklenen kurulum betiği, popüler bir pakete benzeyen ad
ve bilinen güvenlik duyuruları gibi işaretleri raporlar. npm, PyPI, crates.io ve
JSR paketlerini tek bir çalıştırılabilir dosyayla inceler. Hesap açmak gerekmez;
telemetri göndermez.

Bu işaretler tek başına kötü amaçlı kodun kanıtı değildir. Değerlendirilemeyen
kontroller gerekçesiyle `skipped` olarak gösterilir; temiz sonuç sayılmaz.

## Kurulum

Go 1.26 veya üstü kuruluysa:

```sh
go install github.com/vahapogut/trustdiff/cmd/trustdiff@latest
```

macOS'ta Homebrew ile:

```sh
brew install --cask vahapogut/tap/trustdiff
```

Windows'ta Scoop ile:

```powershell
scoop bucket add trustdiff https://github.com/vahapogut/scoop-bucket
scoop install trustdiff
```

Alternatif olarak [sürümler sayfasından](https://github.com/vahapogut/trustdiff/releases)
işletim sisteminize uygun arşivi indirin. İmza, sağlama toplamı ve derleme kaynağı
doğrulama adımları [İngilizce kurulum bölümündedir](../../README.md#install).
macOS Gatekeeper uyarıları ve bunların doğrulama sonrasında nasıl ele alınacağı
da orada açıklanır.

Yayımlanmış CLI sürümü 0.5.2, ayrı yayımlanan Bun tarayıcı paketi 0.5.0'dır.
`main` üzerindeki yeni özellikler yayımlanana kadar `Unreleased` olarak izlenir;
`@latest` komutu henüz yayımlanmamış özellikleri kurmaz.

## Üç kullanım yolu

### 1. Bir bağımlılık eklemeden önce

```sh
trustdiff check npm:express@4.19.2 pypi:requests cargo:serde
trustdiff check package.json
```

Tek paket için `trustdiff check <ecosystem>:<name>[@<version>]` kullanılır.
`ecosystem` değeri `npm`, `pypi`, `cargo` veya `jsr` olabilir. Sürüm verilmezse
ön sürüm olmayan en son sürüm değerlendirilir. `package.json`, `pyproject.toml`
veya `Cargo.toml` verildiğinde doğrudan bağımlılıkların tanımlanan aralıklarla
uyumlu sürümleri çözümlenir. Çözümlenemeyen bağımlılıklar gerekçeleriyle listelenir.

Bun kullanıyorsanız [Bun tarayıcısı](../../integrations/bun-scanner/README.md),
kurulacak paketleri trustdiff'e göndererek engelleyici bulgu durumunda kurulumu
durdurabilir. Kurulu trustdiff dosyasını kullanır:

```toml
# bunfig.toml
[install.security]
scanner = "@trustdiff/bun-scanner"
```

pnpm kurulumu için [pnpm hook kılavuzuna](../../integrations/pnpm-hook/README.md)
bakın. Bu entegrasyonun desteklediği pnpm sürümleri ve dondurulmuş kilit dosyası
davranışı kılavuzda belirtilir; henüz yayımlanmış CLI sürümünün parçası değildir.

### 2. Pull request içindeki değişiklikleri kontrol etmek

```sh
trustdiff diff --format markdown
trustdiff diff --base "$BASE_SHA" --format sarif > trustdiff.sarif
```

`diff`, kilit dosyasında eklenen veya değiştirilen girdileri değerlendirir.
Varsayılan karşılaştırma noktası `origin/main` ile ortak atadır; `--base` ile
başka bir Git referansı seçilebilir. `--format sarif`, kod tarama araçlarına
aktarılabilecek çıktı üretir. [GitHub Action kurulumu](../../README.md#2-a-pull-request-gate)
için İngilizce örnekteki sabit commit referansını kullanın.

```sh
trustdiff scan
trustdiff hook install
```

`scan`, bulunan kilit dosyalarının bütün girdilerini inceler. `hook install`,
commit öncesinde aynı değişiklik kontrolünü çalıştıran yerel Git kancasını kurar.
Dokuz kilit dosyası biçimi desteklenir; biçim ve sürüm ayrıntıları İngilizce
kılavuzdadır.

### 3. Projenin paket yöneticisi ayarlarını denetlemek

```sh
trustdiff doctor
trustdiff doctor --fix
trustdiff doctor --ci
```

`doctor`, paket yöneticisinin sürümünü ve güvenlik ayarlarını denetler. Eksik
ayar, yanlış yazılmış ayar ve geçerli fakat zayıf ayarı ayrı gösterir.
`--fix`, önerilen değişikliği önizleme ve yedekleme akışıyla uygular; mevcut
tercihleri sessizce değiştirmez. `--ci`, politikanın eşiğini aşan sorunlarda
başarısız çıkış kodu verir. Paket yöneticileri bekleme sürelerini farklı
birimlerle ifade ettiği için bu değerleri birbirine doğrudan kopyalamayın.

## Politika ve çevrimdışı kullanım

İstisnalar `.trustdiff.yaml` içinde gerekçeleriyle tutulur; son kullanma tarihi
eklenmesi önerilir. `trustdiff policy validate` dosyayı doğrular. Kontrol adları,
anahtarlar ve değerler çevrilmez:

```yaml
version: 1
cooldown: 3d
checks:
  publisher-changed: block
  install-script-present: warn
on_data_unavailable: warn
```

```sh
trustdiff cache refresh
trustdiff cache status
trustdiff scan --offline
```

`cache refresh`, çevrimdışı güvenlik duyuruları için OSV verisini indirir.
`--offline`, ağ isteklerini kapatır. Önbellekte olmayan veriler için kontrol
atlanır ve nedeni yazılır; çevrimdışı çalışmak her paketin doğrulandığı anlamına
gelmez. Büyük Cargo taramaları için yeni
[crates.io veri dökümü desteği](../crates-dump.md) ayrı ve açık bir yenileme ister.

Normal değerlendirmede çıkış kodları: `0` engelleyici bulgu yok, `1` eşiğe ulaşan
bulgu var, `2` kullanım veya yapılandırma hatası, `3` politika gereği zorunlu
veriye ulaşılamadı. Eşik `--fail-on` ile değiştirilebilir.

## Çevirinin kapsamı ve güncelliği

Bu, giriş, kurulum ve üç temel kullanım yolunun kısmi çevirisidir. Bütün TD/DR
kontrol tabloları, karşılaştırmalar, ayrıntılı kurulum doğrulaması ve tüm politika
seçenekleri henüz çevrilmemiştir; bu konularda İngilizce README'yi okuyun.

<!-- trustdiff-readme-source: d3ff89fad7404e277cc4510d330066caa43d13b4 -->
<!-- trustdiff-readme-blob: c0c36a3b95a223cc96ed14cf513f76476b96b734 -->

Kaynak: [İngilizce README, d3ff89fad7404e277cc4510d330066caa43d13b4](https://github.com/vahapogut/trustdiff/blob/d3ff89fad7404e277cc4510d330066caa43d13b4/README.md).
Çeviri yalnızca bu kaynak sürümüne göre günceldir. Yukarıdaki güncellik kontrolü
başarısızsa İngilizce README çeviriden sonra değişmiş olabilir; geçerli davranışı
İngilizce dosyadan kontrol edin. CI, kaynak commit'teki README ile güncel README
farklıysa çevirinin güncellenmesini ister.
