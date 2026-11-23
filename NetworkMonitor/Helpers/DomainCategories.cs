using System;
using System.Collections.Generic;
using System.IO;

namespace NetworkMonitor.Helpers;

/// <summary>
/// Классификатор доменов по категориям: стриминг, соцсети, реклама и трекеры, CDN, облака и т. д.
/// Встроенный список по суффиксам домена + свои правила в %APPDATA%\NetworkShow\domain-categories.txt
/// (строка: «суффикс[TAB]категория», например «example.org\tРабота»).
/// </summary>
public static class DomainCategories
{
    public const string Streaming = "Стриминг (видео, музыка)";
    public const string Social = "Соцсети и мессенджеры";
    public const string Ads = "Реклама и трекеры";
    public const string Cdn = "CDN";
    public const string Cloud = "Облако и хостинг";
    public const string Updates = "Обновления ОС и ПО";
    public const string Games = "Игры";
    public const string Search = "Поиск, почта, сервисы";
    public const string Shopping = "Магазины и платежи";
    public const string Dev = "Разработка";
    public const string Vpn = "VPN и приватность";

    private static readonly Dictionary<string, string> Map = Build();
    private static Dictionary<string, string>? _user;

    public static string Classify(string? host)
    {
        if (string.IsNullOrEmpty(host)) return string.Empty;
        var h = host.TrimEnd('.').ToLowerInvariant();
        var user = _user ??= LoadUser();
        // от полного имени к родительским суффиксам: a.b.example.com → b.example.com → example.com
        var s = h;
        while (true)
        {
            if (user.TryGetValue(s, out var uc)) return uc;
            if (Map.TryGetValue(s, out var c)) return c;
            int dot = s.IndexOf('.');
            if (dot < 0 || dot == s.Length - 1) break;
            s = s[(dot + 1)..];
            if (s.IndexOf('.') < 0) break; // голый TLD не проверяем
        }
        return string.Empty;
    }

    /// <summary>Грубая категория по названию провайдера (ASN), когда у соединения нет имени хоста.</summary>
    public static string FromAsnOrg(string? asnText)
    {
        if (string.IsNullOrEmpty(asnText)) return string.Empty;
        var t = asnText.ToLowerInvariant();
        string[] cdn = { "cloudflare", "akamai", "fastly", "cdn77", "edgecast", "stackpath", "bunny", "cachefly", "limelight", "edgio" };
        foreach (var k in cdn) if (t.Contains(k)) return Cdn;
        string[] cloud = { "amazon", "microsoft", "google", "digitalocean", "hetzner", "ovh", "linode", "oracle", "alibaba", "tencent", "vultr", "selectel", "yandex cloud", "scaleway", "contabo", "hosting", "vds", "datacenter", "data center", "cloud" };
        foreach (var k in cloud) if (t.Contains(k)) return Cloud;
        if (t.Contains("facebook") || t.Contains("meta platforms") || t.Contains("telegram") || t.Contains("twitter") || t.Contains("vkontakte") || t.Contains("snap")) return Social;
        if (t.Contains("netflix") || t.Contains("spotify")) return Streaming;
        return string.Empty;
    }

    public static void ReloadUserRules() => _user = LoadUser();

    private static Dictionary<string, string> LoadUser()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetworkShow", "domain-categories.txt");
            if (!File.Exists(path)) return map;
            foreach (var line in File.ReadAllLines(path))
            {
                var l = line.Trim();
                if (l.Length == 0 || l[0] == '#') continue;
                var parts = l.Split('\t', 2);
                if (parts.Length == 2 && parts[0].Length > 2 && parts[1].Length > 0) map[parts[0].Trim().ToLowerInvariant()] = parts[1].Trim();
            }
        }
        catch { }
        return map;
    }

    private static Dictionary<string, string> Build()
    {
        var m = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Add(string category, params string[] domains) { foreach (var d in domains) m[d] = category; }

        Add(Streaming, "youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net",
            "twitch.tv", "ttvnw.net", "jtvnw.net", "spotify.com", "scdn.co", "spotifycdn.com", "kinopoisk.ru", "ivi.ru", "okko.tv", "wink.ru",
            "premier.one", "more.tv", "start.ru", "disneyplus.com", "dssott.com", "primevideo.com", "hbomax.com", "max.com", "tiktok.com", "tiktokcdn.com",
            "tiktokv.com", "deezer.com", "soundcloud.com", "music.yandex.ru", "zvuk.com", "vimeo.com", "rutube.ru", "dailymotion.com", "kion.ru", "tv.yandex.ru",
            "plex.tv", "crunchyroll.com", "boom.ru", "music.apple.com", "apple-music", "hulu.com", "pluto.tv");
        Add(Social, "facebook.com", "fbcdn.net", "fb.com", "instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net", "messenger.com",
            "twitter.com", "x.com", "twimg.com", "t.co", "vk.com", "vk.ru", "userapi.com", "vkuser.net", "vk-cdn.net", "vkuseraudio.net", "ok.ru", "mycdn.me",
            "telegram.org", "t.me", "telegram.me", "cdn-telegram.org", "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
            "reddit.com", "redditmedia.com", "redd.it", "redditstatic.com", "linkedin.com", "licdn.com", "snapchat.com", "sc-cdn.net", "pinterest.com", "pinimg.com",
            "viber.com", "signal.org", "slack.com", "slack-edge.com", "zoom.us", "zoom.com", "skype.com", "teams.microsoft.com", "line.me", "line-scdn.net",
            "tumblr.com", "threads.net", "mastodon.social", "bsky.app", "bsky.social", "tgcdn.org");
        Add(Ads, "doubleclick.net", "googlesyndication.com", "googleadservices.com", "googletagmanager.com", "googletagservices.com", "google-analytics.com",
            "adservice.google.com", "pagead2.googlesyndication.com", "2mdn.net", "adnxs.com", "adsrvr.org", "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
            "hotjar.com", "hotjar.io", "mixpanel.com", "segment.io", "segment.com", "scorecardresearch.com", "quantserve.com", "rubiconproject.com", "pubmatic.com",
            "openx.net", "amazon-adsystem.com", "appsflyer.com", "adjust.com", "branch.io", "amplitude.com", "mc.yandex.ru", "mc.yandex.com", "an.yandex.ru",
            "yandexadexchange.net", "adfox.ru", "top.mail.ru", "counter.yadro.ru", "mail.ru/counter", "mradx.net", "tns-counter.ru", "liveinternet.ru", "yastatic.net/metrika",
            "connect.facebook.net", "pixel.facebook.com", "analytics.twitter.com", "ads-twitter.com", "static.ads-twitter.com", "ads.linkedin.com", "bat.bing.com",
            "clarity.ms", "sentry.io", "newrelic.com", "nr-data.net", "datadoghq.com", "fullstory.com", "crazyegg.com", "moatads.com", "adform.net", "smartadserver.com",
            "yieldmo.com", "casalemedia.com", "bidswitch.net", "mathtag.com", "demdex.net", "omtrdc.net", "everesttech.net", "tiktokv.us", "app-measurement.com",
            "firebase-settings.crashlytics.com", "crashlytics.com", "events.data.microsoft.com", "vortex.data.microsoft.com", "telemetry.microsoft.com", "watson.telemetry.microsoft.com");
        Add(Cdn, "cloudflare.com", "cloudflare.net", "cloudflarestorage.com", "cdnjs.com", "jsdelivr.net", "unpkg.com", "akamai.net", "akamaiedge.net", "akamaihd.net",
            "akamaitechnologies.com", "edgekey.net", "edgesuite.net", "fastly.net", "fastlylb.net", "fastly.com", "cloudfront.net", "azureedge.net", "azurefd.net",
            "edgecastcdn.net", "cdn77.org", "b-cdn.net", "bunnycdn.com", "stackpathcdn.com", "gstatic.com", "googleusercontent.com", "ggpht.com", "cachefly.net",
            "cdn.jsdelivr.net", "ytimg.com/vi", "staticflickr.com", "cdn.cloudflare.net", "llnwd.net", "hwcdn.net", "kxcdn.com", "cdn.ampproject.org", "yandex.net",
            "yastatic.net", "mail.ru/static", "imgsmail.ru", "mrgcdn.ru", "ngenix.net", "selcdn.ru", "gcore.com", "gcdn.co", "cdnvideo.ru");
        Add(Cloud, "amazonaws.com", "aws.amazon.com", "awsstatic.com", "azure.com", "azurewebsites.net", "windows.net", "core.windows.net", "cloudapp.azure.com",
            "digitalocean.com", "digitaloceanspaces.com", "hetzner.com", "hetzner.cloud", "ovh.net", "ovh.com", "linode.com", "vultr.com", "oraclecloud.com", "alibabacloud.com",
            "aliyuncs.com", "myqcloud.com", "yandexcloud.net", "selectel.ru", "timeweb.cloud", "timeweb.ru", "beget.com", "beget.tech", "reg.ru", "hosting.reg.ru",
            "firebaseio.com", "appspot.com", "run.app", "cloudfunctions.net", "herokuapp.com", "netlify.app", "vercel.app", "github.io", "githubusercontent.com",
            "storage.googleapis.com", "drive.google.com", "dropbox.com", "dropboxusercontent.com", "box.com", "onedrive.com", "1drv.com", "sharepoint.com", "icloud.com",
            "cloud.mail.ru", "disk.yandex.ru", "yadi.sk", "mega.nz", "mega.io", "backblazeb2.com", "wasabisys.com", "ngrok.io", "ngrok-free.app", "tailscale.com", "ts.net",
            "my-vm.work", "hosting-vds.com", "vds.sh", "ru.net", "serverel.net");
        Add(Updates, "windowsupdate.com", "update.microsoft.com", "download.microsoft.com", "delivery.mp.microsoft.com", "dl.delivery.mp.microsoft.com", "tlu.dl.delivery.mp.microsoft.com",
            "windows.com", "microsoft.com", "msftconnecttest.com", "msedge.net", "edge.microsoft.com", "live.com", "office.com", "office.net", "officeapps.live.com", "msauth.net",
            "apple.com", "swcdn.apple.com", "mzstatic.com", "cdn-apple.com", "ubuntu.com", "canonical.com", "debian.org", "archlinux.org", "fedoraproject.org", "mozilla.org", "mozilla.net",
            "firefox.com", "google.com/chrome", "dl.google.com", "gvt1.com", "gvt2.com", "adobe.com", "adobe.io", "adobelogin.com", "java.com", "oracle.com/java", "nvidia.com", "nvidia.net",
            "intel.com", "amd.com", "avast.com", "avcdn.net", "kaspersky.com", "kaspersky-labs.com", "drweb.com", "eset.com", "windowsupdate.microsoft.com", "wustat.windows.com");
        Add(Games, "steampowered.com", "steamcontent.com", "steamstatic.com", "steamcommunity.com", "steamserver.net", "valve.net", "epicgames.com", "epicgames.dev", "unrealengine.com",
            "riotgames.com", "leagueoflegends.com", "battle.net", "blizzard.com", "battlenet.com.cn", "ea.com", "origin.com", "ubisoft.com", "ubi.com", "xboxlive.com", "xbox.com",
            "playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "nintendo.com", "nintendo.net", "roblox.com", "rbxcdn.com", "minecraft.net", "mojang.com",
            "wargaming.net", "worldoftanks.eu", "worldoftanks.ru", "lesta.ru", "mail.ru/games", "my.games", "vkplay.ru", "gaijin.net", "warthunder.com", "faceit.com", "twitch.tv/games",
            "gog.com", "gog-statics.com", "itch.io", "playgalaxy.com", "garena.com", "mihoyo.com", "hoyoverse.com", "genshin.hoyoverse.com", "pubg.com", "krafton.com", "supercell.com", "clashofclans.com");
        Add(Search, "google.com", "google.ru", "googleapis.com", "gmail.com", "bing.com", "yandex.ru", "yandex.com", "ya.ru", "mail.ru", "rambler.ru", "duckduckgo.com", "yahoo.com",
            "outlook.com", "outlook.office365.com", "proton.me", "protonmail.com", "wikipedia.org", "wikimedia.org", "yandex.net/mail", "gosuslugi.ru", "nalog.gov.ru", "mos.ru",
            "2gis.ru", "2gis.com", "maps.google.com", "openstreetmap.org", "translate.google.com", "deepl.com", "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "perplexity.ai");
        Add(Shopping, "ozon.ru", "ozone.ru", "wildberries.ru", "wb.ru", "wbstatic.net", "aliexpress.com", "alicdn.com", "amazon.com", "amazon.de", "ebay.com", "avito.ru", "avito.st",
            "market.yandex.ru", "sbermegamarket.ru", "dns-shop.ru", "citilink.ru", "mvideo.ru", "eldorado.ru", "lamoda.ru", "paypal.com", "stripe.com", "stripe.network", "sberbank.ru", "sber.ru",
            "tinkoff.ru", "tbank.ru", "vtb.ru", "alfabank.ru", "raiffeisen.ru", "yoomoney.ru", "yookassa.ru", "qiwi.com", "visa.com", "mastercard.com", "nspk.ru", "mir-pay.ru", "sbp.nspk.ru");
        Add(Dev, "github.com", "githubassets.com", "gitlab.com", "bitbucket.org", "npmjs.org", "npmjs.com", "nuget.org", "pypi.org", "pythonhosted.org", "crates.io", "rubygems.org",
            "docker.io", "docker.com", "gcr.io", "ghcr.io", "quay.io", "stackoverflow.com", "stackexchange.com", "visualstudio.com", "vsassets.io", "jetbrains.com", "dot.net", "dotnet.microsoft.com",
            "golang.org", "go.dev", "rust-lang.org", "maven.org", "gradle.org", "hashicorp.com", "terraform.io", "vscode-cdn.net", "vsmarketplacebadges.dev", "anaconda.org", "conda.io", "huggingface.co");
        Add(Vpn, "nordvpn.com", "nordcdn.com", "expressvpn.com", "protonvpn.com", "mullvad.net", "windscribe.com", "surfshark.com", "privateinternetaccess.com", "torproject.org", "hide.me",
            "cyberghostvpn.com", "tunnelbear.com", "psiphon.ca", "lantern.io", "outline.network", "wireguard.com", "openvpn.net");
        return m;
    }
}
