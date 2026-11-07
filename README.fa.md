<div align="center">

<img src="docs/logo.svg" width="96" alt="لوگوی Phi2ray" />

# Phi2ray

**کلاینت Xray برای ویندوز و لینوکس که تمام تلاشش را می‌کند چیزی لو نرود.🐱**

[![Latest release](https://img.shields.io/github/v/release/Phoenix15049/Phi2ray?label=release&color=6c5cf6)](https://github.com/Phoenix15049/Phi2ray/releases/latest)
![Windows 10 / 11](https://img.shields.io/badge/Windows-10%20%7C%2011-1fb6d0)
![Linux](https://img.shields.io/badge/Linux-deb%20%7C%20rpm%20%7C%20Arch%20%7C%20AppImage-1fb6d0)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ee6a6)](LICENSE)

[دانلود](https://github.com/Phoenix15049/Phi2ray/releases/latest) · [English](README.md)

<br />

<img src="docs/screenshot-fa.jpg" width="280" alt="Phi2ray به زبان فارسی" />
&nbsp;
<img src="docs/screenshot-dark.jpg" width="280" alt="Phi2ray با پوسته‌ی تیره" />
&nbsp;
<img src="docs/screenshot-light.jpg" width="280" alt="Phi2ray با پوسته‌ی روشن" />

</div>

<div dir="rtl">

---

لینک را paste می‌کنید، دکمه‌ی بزرگ را می‌زنید و کل کامپیوترتان از سرور شما عبور می‌کند. اگر اتصال قطع
شود، ترافیک منتظر می‌ماند تا اتصال برگردد، نه اینکه بی‌صدا از اینترنت واقعی شما خارج شود. Phi2ray بیشتر
از هر چیز درباره‌ی همین است.

## چرا ساختمش

هر روز با کانفیگ‌های Xray کار می‌کنم و مدام به دو مشکل می‌خوردم. بعضی کلاینت‌ها آن‌قدر گزینه داشتند که
هیچ‌وقت مطمئن نبودم چه چیزی را روشن کرده‌ام. بعضی دیگر ساده بودند، ولی کارهایی می‌کردند که خیالم را
راحت نمی‌کرد: پورت SOCKS باز روی `1080` که هر برنامه‌ای پیدایش می‌کرد، DNS که مستقیم به اپراتور می‌رفت،
و چند ثانیه نشتی هر بار که اتصال می‌لرزید.

برای همین خودم یکی نوشتم. پروتکل‌ها با [Xray-core](https://github.com/XTLS/Xray-core) است و آداپتور VPN
با [sing-box](https://github.com/SagerNet/sing-box). Phi2ray برنامه‌ی کوچکی به زبان Rust است که این دو را
امن راه می‌اندازد، حواسش به آن‌ها هست و مزاحم شما نمی‌شود.

## نصب

فایل سیستم خودتان را از [آخرین نسخه](https://github.com/Phoenix15049/Phi2ray/releases/latest) بگیرید.

| سیستم شما | فایل |
|---|---|
| ویندوز ۱۰ و ۱۱ | `Phi2ray-<version>-windows-x64.exe` |
| Ubuntu، Debian، Linux Mint، Pop!_OS، Zorin، Kali | `Phi2ray-<version>-linux-amd64.deb` |
| Fedora، RHEL، AlmaLinux، Rocky | `Phi2ray-<version>-linux-x86_64.rpm` |
| Arch، Manjaro، EndeavourOS | `phi2ray-bin-<version>-1-x86_64.pkg.tar.zst` |
| بقیه، از جمله openSUSE | `Phi2ray-<version>-linux-x86_64.AppImage` |

نسخه‌های لینوکس برای پردازنده‌های ۶۴ بیتی اینتل و AMD هستند و Ubuntu 22.04، Debian 12، Fedora 38 یا
جدیدتر می‌خواهند.

### ویندوز

فایل exe را اجرا کنید. ویندوز دسترسی ادمین می‌خواهد که آداپتور VPN و قوانین فایروال به آن نیاز دارند.
نصب لازم نیست.

فایل هنوز امضای دیجیتال ندارد، پس ممکن است ویندوز آن را «ناشناس» بنامد. روی *More info* و بعد
*Run anyway* بزنید.

### لینوکس

از پوشه‌ای که فایل را دانلود کرده‌اید، با ابزار خود سیستم نصبش کنید:

</div>

```bash
sudo apt install ./Phi2ray-*-linux-amd64.deb
```

```bash
sudo dnf install ./Phi2ray-*-linux-x86_64.rpm
```

```bash
sudo pacman -U phi2ray-bin-*.pkg.tar.zst
```

<div dir="rtl">

بعد Phi2ray را از منوی برنامه‌ها باز کنید.

AppImage نصب نمی‌خواهد. قابل اجرایش کنید و بازش کنید:

</div>

```bash
chmod +x Phi2ray-*-linux-x86_64.AppImage
./Phi2ray-*-linux-x86_64.AppImage
```

<div dir="rtl">

بار اولی که در حالت VPN وصل می‌شوید، سیستم رمز عبورتان را می‌پرسد. AppImage همان بار اول دو بار می‌پرسد،
چون helper خودش را هم در `/opt/phi2ray` کپی می‌کند. بعد از آن، هر بار که Phi2ray را باز کنید یک بار
می‌پرسد.

## شروع کار

۱. روی **Add** بزنید و لینک یا آدرس اشتراک را paste کنید.

۲. دکمه‌ی پاور را بزنید.

همین. همه‌ی تنظیمات مقدار پیش‌فرض مناسبی دارند.

## چه چیزهایی دارد

**اتصال**

- لینک‌های `vless://`، `vmess://`، `trojan://` و `ss://` و لیست‌های base64، با REALITY، XHTTP،
  WebSocket، gRPC، HTTPUpgrade و TLS.
- اشتراک‌هایی که خودشان به‌روز می‌شوند و حجم و روز باقی‌مانده را نشان می‌دهند.
- سه حالت: **VPN** برای کل سیستم، **پروکسی سیستم** برای برنامه‌هایی که از تنظیمات پروکسی سیستم پیروی
  می‌کنند، و **فقط پروکسی** اگر خودتان می‌خواهید برنامه‌ها را تنظیم کنید.
- تست واقعی: از هر سرور یک درخواست رد می‌شود، پس سروری که روشن است ولی کار نمی‌کند ناموفق نشان داده
  می‌شود. کنار سرورهای ناامن یک ⚠ کوچک می‌آید.

**لو نرفتن**

- **کیل‌سوئیچ.** قوانین فایروال جز تونل چیزی را بیرون نمی‌گذارند، حتی موقع اتصال دوباره یا عوض کردن سرور.
  اگر Phi2ray کرش کند مسدودسازی می‌ماند و چیزی لو نمی‌رود. Phi2ray را باز کنید تا دوباره وصل شوید یا
  مسدودسازی را بردارید. ری‌استارت کامپیوتر هم همیشه آن را پاک می‌کند.
- **اتصال دوباره بدون رها کردن.** فقط تکه‌ی خراب از نو شروع می‌شود. برنامه‌ها چند ثانیه صبر می‌کنند و به
  اینترنت واقعی برنمی‌گردند.
- **DNS از داخل تونل** با HTTPS، با دکمه‌ی *Test* برای پیدا کردن سریع‌ترین سرور.
- **اطلاعات اتصال** (دکمه‌ی ⓘ) آی‌پی خروجی و موقعیت را روی نقشه نشان می‌دهد، به آی‌پی از ۰ تا ۱۰۰ نمره
  می‌دهد و لیست‌های سیاه عمومی را چک می‌کند. فقط وقتی بازش کنید اجرا می‌شود.

**کار روزمره**

- **Split tunnel.** بعضی برنامه‌ها و سایت‌ها را از VPN رد نکنید، یا فقط همان‌هایی را که می‌خواهید از آن
  عبور دهید.
- دو پرتوی صفحه‌ی اصلی دانلود و آپلود شما هستند و با ترافیک واقعی حرکت می‌کنند.
- آیکون سینی وضعیت را در یک نگاه نشان می‌دهد. پوسته‌ی تیره و روشن و رابط کامل فارسی هم دارد.

**از ترمینال**

*Settings → Console* را روشن کنید، یک ترمینال تازه باز کنید و:

</div>

```bash
phi2ray                    # where things stand
phi2ray connect Germany    # by number, name or id; no name = the selected one
phi2ray disconnect
phi2ray servers
phi2ray test
phi2ray mode proxy         # vpn, proxy or manual
phi2ray killswitch off
phi2ray add                # the links you copied
phi2ray logs -f
phi2ray help
```

<div dir="rtl">

همه‌ی دستورها `--json` را می‌پذیرند. کد خروج در موفقیت ۰، در خطا ۱، برای اشتباه تایپی ۲ و وقتی Phi2ray
اجرا نیست ۳ است. لینک‌ها رمز شما را در خود دارند، پس آن‌ها را جلوی `phi2ray add` تایپ نکنید، چون شل
تاریخچه نگه می‌دارد. اول کپی‌شان کنید یا با `phi2ray add -` به آن pipe کنید.

## ساخت از روی سورس

به [Rust](https://rustup.rs) و [Node.js](https://nodejs.org) نسخه‌ی ۲۰ یا جدیدتر نیاز دارید.

</div>

```bash
git clone https://github.com/Phoenix15049/Phi2ray.git
cd Phi2ray
npm install
```

<div dir="rtl">

**در لینوکس** کتابخانه‌ها را نصب کنید (این لیست برای Ubuntu و Debian است)، هسته‌ها را بگیرید و بیلد کنید:

</div>

```bash
sudo apt install build-essential libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf file rpm
```

```bash
sh scripts/get-linux-cores.sh
```

```bash
npm run build:linux
```

<div dir="rtl">

بسته‌ها در `src-tauri/target/release/bundle/` ساخته می‌شوند.

**در ویندوز** ابزارهای C++ ویژوال استودیو را هم لازم دارید. هسته‌ها را دستی در `src-tauri/core/`
بگذارید ([کدام فایل‌ها](src-tauri/core/README.md)) و بعد:

</div>

```bash
npm run build:exe
```

<div dir="rtl">

فایل در `src-tauri/target/release/phi2ray.exe` ساخته می‌شود.

هر دو بیلد همه‌ی هسته‌ها را با هش‌های ثبت‌شده در `src-tauri/core` مقایسه می‌کنند و اگر یکی نخواند متوقف
می‌شوند.

**برای کار روی پروژه:**

</div>

```bash
npm run dev
```

<div dir="rtl">

رابط را با داده‌ی ساختگی در مرورگر باز می‌کند و به شبکه‌ی شما دست نمی‌زند.

</div>

```bash
npm run tauri dev
```

<div dir="rtl">

برنامه‌ی واقعی را اجرا می‌کند. برای حالت VPN، در ویندوز ترمینال را با دسترسی ادمین باز کنید و در لینوکس
اول یک بسته نصب کنید تا helper موجود باشد.

## این فایل واقعاً مال شماست؟

نسخه‌ها را GitHub Actions مستقیماً از کامیت تگ‌خورده می‌سازد ([workflow](.github/workflows/release.yml))،
نه کامپیوتر من، و فقط اگر بررسی وابستگی‌ها پاس شود و همه‌ی هسته‌ها با هش ثبت‌شده بخوانند. SHA-256 فایل را
با یادداشت نسخه مقایسه کنید، یا گواهی امضاشده‌ی بیلد را چک کنید:

</div>

```bash
gh attestation verify <file> -R Phoenix15049/Phi2ray
```

<div dir="rtl">

## سوال‌های رایج

**گوگل فکر می‌کند ایرانم، ولی بقیه‌ی سایت‌ها کشور سرور را نشان می‌دهند.**
این پایگاه‌داده‌ی موقعیت خود گوگل است، نه نشتی. اگر [ipleak.net](https://ipleak.net) و
[browserleaks.com/webrtc](https://browserleaks.com/webrtc) آی‌پی یا DNS ایرانی نشان ندهند، مشکلی نیست.

**می‌گوید وصل است، ولی چیزی باز نمی‌شود.**
دکمه نارنجی می‌شود و «No internet» می‌نویسد. سطح لاگ را در تنظیمات روی *Info* بگذارید، دوباره وصل شوید
و Logs را باز کنید. دلیل معمولاً همان‌جاست.

**Split tunnel برای برنامه‌ها در حالت پروکسی سیستم کار نمی‌کند.**
طبیعی است. فقط حالت VPN می‌بیند هر اتصال از کدام برنامه است. سایت‌ها در همه‌ی حالت‌ها کار می‌کنند.

**بعضی کانفیگ‌های VLESS بدون TLS وصل نمی‌شوند.**
نسخه‌های جدید Xray، VLESS بدون رمزنگاری را رد می‌کنند، مگر اینکه سرور در شبکه‌ی خصوصی باشد.

**لینوکس: رمز عبور نمی‌پرسد و حالت VPN خطا می‌دهد.**
سیستم برای پرسیدن رمز به یک polkit agent نیاز دارد. میزکارهایی مثل GNOME، KDE، Cinnamon و Xfce آن را
دارند. روی یک window manager ساده خودتان یکی اجرا کنید، مثل `lxpolkit`.

**لینوکس: آیکون سینی را نمی‌بینم.**
GNOME آیکون‌های سینی را نشان نمی‌دهد، مگر با افزونه‌ی AppIndicator که Ubuntu به‌طور پیش‌فرض دارد. برای
همین *کوچک‌سازی به سینی* در لینوکس از ابتدا خاموش است.

**لینوکس: حالت پروکسی سیستم می‌گوید میزکارم پشتیبانی نمی‌شود.**
این حالت روی GNOME، KDE و میزکارهای مبتنی بر تنظیمات آن‌ها کار می‌کند. در بقیه از حالت VPN استفاده کنید.

## بیشتر بخوانید

- [Phi2ray چطور کار می‌کند](docs/how-it-works.md) (انگلیسی): کیل‌سوئیچ، helper لینوکس، بقیه‌ی جزئیات و
  اینکه چه چیزهایی از تونل رد نمی‌شوند.
- [سیاست حریم خصوصی](PRIVACY.md). هیچ تله‌متری، آمارگیری یا چک آپدیتی وجود ندارد.
- [سیاست امضای کد](CODE_SIGNING.md) که روش حذف Phi2ray را هم توضیح می‌دهد.

## تشکر

بدون [Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0)،
[sing-box](https://github.com/SagerNet/sing-box) (GPL-3.0) و [Tauri](https://tauri.app) هیچ‌کدام از این‌ها
وجود نداشت. مجوزها و لینک سورس‌شان در [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) است.

## مجوز

کد خود Phi2ray با [مجوز MIT](LICENSE) منتشر شده و هسته‌ها مجوز خودشان را دارند. مسئولانه و مطابق قوانین
محل زندگی‌تان از آن استفاده کنید.

اگر باگی دیدید یا ایده‌ای داشتید، [یک issue باز کنید](https://github.com/Phoenix15049/Phi2ray/issues).
همه را می‌خوانم.

</div>
