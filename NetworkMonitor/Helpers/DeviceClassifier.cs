using System;
using System.Collections.Generic;

namespace NetworkMonitor.Helpers;

/// <summary>Предположение о типе устройства по производителю (OUI), имени хоста и признакам (mDNS/SSDP/DHCP). Это эвристика, а не точное определение.</summary>
public static class DeviceClassifier
{
    public static string Guess(string vendor, string hostName, IEnumerable<string> hints, bool isGateway, bool isRandomMac)
    {
        if (isGateway) return "Роутер / шлюз";

        var blob = (vendor + " | " + hostName + " | " + string.Join(" | ", hints)).ToLowerInvariant();
        bool Has(params string[] keys) { foreach (var k in keys) if (blob.Contains(k)) return true; return false; }

        if (Has("androidtvremote", "_androidtv")) return "Android TV (телевизор / приставка)";
        if (Has("googlecast", "chromecast")) return "Chromecast / Android TV / Google TV";
        if (Has("roku")) return "Roku (приставка / ТВ)";
        if (Has("amazon") && Has("fire", "amzn")) return "Amazon Fire TV";
        if (Has("airplay", "raop", "_companion-link") && Has("apple")) return "Apple (iPhone / Apple TV / Mac)";
        if (Has("_ipp", "_printer", "_pdl-datastream", "принтер") || Has("canon", "epson", "brother", "hewlett", "xerox", "kyocera") && Has("print"))
            return "Принтер / МФУ";
        if (Has("android-dhcp", "android_") || hostName.StartsWith("android-", StringComparison.OrdinalIgnoreCase))
            return Has("googlecast", "tv", "box") ? "Android-приставка / ТВ" : "Android-устройство (телефон / приставка)";
        if (Has("mediarenderer", "dial-multiscreen"))
            return Has("samsung", "lg electronics", "tcl", "hisense", "sony", "panasonic", "philips", "vizio", "toshiba", "sharp", "haier")
                ? "Телевизор (Smart TV)" : "Медиаплеер / Smart TV (DLNA)";
        if (Has("samsung electronics") && Has("tizen", "smarttv", "upnp")) return "Телевизор Samsung";
        if (Has("tcl", "hisense", "skyworth", "changhong", "vizio", "sharp", "toshiba", "haier", "panasonic", "philips", "tp vision", "lg electronics"))
            return "Телевизор (вероятно)";
        if (Has("amlogic", "rockchip", "allwinner", "shenzhen") && !Has("intel")) return "Android-приставка (вероятно)";
        if (Has("ampak")) return "Устройство с Wi-Fi модулем AMPAK (часто Android-приставка / ТВ)";
        if (Has("xiaomi", "mi-", "redmi")) return "Устройство Xiaomi (телефон / приставка / IoT)";
        if (Has("espressif", "tuya", "shelly", "sonoff", "_hap._tcp", "yeelight")) return "Умный дом / IoT";
        if (Has("raspberry")) return "Raspberry Pi";
        if (Has("sony interactive", "microsoft") && Has("xbox", "playstation", "sony interactive")) return "Игровая консоль";
        if (Has("intel", "dell", "lenovo", "asus", "hewlett", "acer", "msi", "gigabyte", "micro-star", "realtek", "_smb._tcp", "_workstation", "desktop-", "laptop-", "-pc"))
            return "Компьютер / ноутбук";
        if (Has("apple")) return "Устройство Apple";
        if (Has("samsung", "huawei", "oppo", "vivo", "oneplus", "motorola", "realme", "honor", "google")) return "Телефон / планшет (вероятно)";
        if (Has("tp-link", "keenetic", "mikrotik", "zyxel", "d-link", "netgear", "ubiquiti", "tenda", "huawei technologies")) return "Сетевое оборудование";
        if (isRandomMac) return "Телефон / планшет (случайный MAC)";
        return "Не определено";
    }
}
