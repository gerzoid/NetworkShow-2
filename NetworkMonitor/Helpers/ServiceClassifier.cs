using System;

namespace NetworkMonitor.Helpers;

public static class ServiceClassifier
{
    private static readonly (string Pattern, string Label)[] Rules =
    {
        // --- SignalR ---
        ("*.service.signalr.net", "SignalR"),
        ("*.signalr.net", "SignalR"),
        ("*.liveshare.vsengsaas.visualstudio.com", "VS Live Share (SignalR)"),
        ("*.signalr.*", "SignalR"),

        // --- Microsoft / Office / Azure ---
        ("*.teams.microsoft.com", "Teams"),
        ("*.teams.cdn.office.net", "Teams"),
        ("*.teams.skype.com", "Teams"),
        ("*.skype.com", "Skype"),
        ("*.lync.com", "Teams (Lync)"),
        ("*.outlook.office365.com", "Outlook"),
        ("*.outlook.office.com", "Outlook"),
        ("*.outlook.com", "Outlook"),
        ("*.office.com", "Office365"),
        ("*.office.net", "Office365"),
        ("*.officeapps.live.com", "Office365"),
        ("*.office365.com", "Office365"),
        ("*.sharepoint.com", "SharePoint"),
        ("*.onedrive.com", "OneDrive"),
        ("*.1drv.com", "OneDrive"),
        ("*.windowsupdate.com", "WindowsUpdate"),
        ("*.update.microsoft.com", "WindowsUpdate"),
        ("*.delivery.mp.microsoft.com", "WindowsUpdate"),
        ("*.dl.delivery.mp.microsoft.com", "WindowsUpdate"),
        ("*.events.data.microsoft.com", "MS Telemetry"),
        ("*.vortex.data.microsoft.com", "MS Telemetry"),
        ("*.telemetry.microsoft.com", "MS Telemetry"),
        ("*.smartscreen.microsoft.com", "MS SmartScreen"),
        ("*.msftncsi.com", "MS NCSI"),
        ("*.msftconnecttest.com", "MS Connect Test"),
        ("*.bing.com", "Bing"),
        ("*.bingapis.com", "Bing"),
        ("*.cognitiveservices.azure.com", "Azure AI"),
        ("*.openai.azure.com", "Azure OpenAI"),
        ("*.applicationinsights.azure.com", "AppInsights"),
        ("*.applicationinsights.io", "AppInsights"),
        ("dc.services.visualstudio.com", "AppInsights"),
        ("*.azure.com", "Azure"),
        ("*.azureedge.net", "Azure CDN"),
        ("*.azurefd.net", "Azure Front Door"),
        ("*.blob.core.windows.net", "Azure Blob"),
        ("*.queue.core.windows.net", "Azure Queue"),
        ("*.table.core.windows.net", "Azure Table"),
        ("*.file.core.windows.net", "Azure Files"),
        ("*.servicebus.windows.net", "Azure ServiceBus"),
        ("*.visualstudio.com", "VisualStudio"),
        ("*.vsassets.io", "VisualStudio"),
        ("*.visualstudio.microsoft.com", "VisualStudio"),
        ("time.windows.com", "NTP"),
        ("*.windows.com", "Windows"),
        ("*.windows.net", "Windows"),
        ("*.live.com", "Live"),
        ("*.live.net", "Live"),
        ("*.microsoft.com", "Microsoft"),
        ("*.msn.com", "MSN"),

        // --- Code / Devtools ---
        ("api.github.com", "GitHub API"),
        ("*.copilot.github.com", "Copilot"),
        ("*.githubcopilot.com", "Copilot"),
        ("*.github.com", "GitHub"),
        ("github.com", "GitHub"),
        ("*.githubusercontent.com", "GitHub"),
        ("*.githubassets.com", "GitHub"),
        ("*.gitlab.com", "GitLab"),
        ("*.bitbucket.org", "Bitbucket"),
        ("registry.npmjs.org", "npm"),
        ("*.npmjs.com", "npm"),
        ("*.npmjs.org", "npm"),
        ("*.nuget.org", "NuGet"),
        ("hub.docker.com", "Docker Hub"),
        ("*.docker.io", "Docker"),
        ("*.docker.com", "Docker"),
        ("*.jetbrains.com", "JetBrains"),

        // --- Anthropic / OpenAI / AI ---
        ("api.anthropic.com", "Anthropic API"),
        ("*.anthropic.com", "Anthropic"),
        ("claude.ai", "Claude"),
        ("*.claude.ai", "Claude"),
        ("api.openai.com", "OpenAI"),
        ("chat.openai.com", "ChatGPT"),
        ("*.openai.com", "OpenAI"),

        // --- Google ---
        ("*.googleapis.com", "Google API"),
        ("*.google.com", "Google"),
        ("*.gstatic.com", "Google"),
        ("*.googleusercontent.com", "Google"),
        ("*.youtube.com", "YouTube"),
        ("*.googlevideo.com", "YouTube"),
        ("*.ytimg.com", "YouTube"),
        ("*.doubleclick.net", "Google Ads"),
        ("*.googletagmanager.com", "Google Tag"),
        ("*.google-analytics.com", "Google Analytics"),
        ("*.firebaseio.com", "Firebase"),
        ("*.gvt1.com", "Google Update"),
        ("*.gvt2.com", "Google Update"),

        // --- Apple ---
        ("*.itunes.apple.com", "iTunes"),
        ("*.time.apple.com", "NTP"),
        ("*.apple.com", "Apple"),
        ("*.icloud.com", "iCloud"),
        ("*.mzstatic.com", "Apple"),
        ("*.cdn-apple.com", "Apple CDN"),

        // --- Meta ---
        ("*.facebook.com", "Facebook"),
        ("*.fbcdn.net", "Facebook"),
        ("*.instagram.com", "Instagram"),
        ("*.cdninstagram.com", "Instagram"),
        ("*.whatsapp.net", "WhatsApp"),
        ("*.whatsapp.com", "WhatsApp"),

        // --- Streaming / chat ---
        ("*.discord.com", "Discord"),
        ("*.discord.gg", "Discord"),
        ("*.discordapp.com", "Discord"),
        ("*.discordapp.net", "Discord"),
        ("*.telegram.org", "Telegram"),
        ("*.t.me", "Telegram"),
        ("*.tdesktop.com", "Telegram"),
        ("*.slack.com", "Slack"),
        ("*.slack-edge.com", "Slack"),
        ("*.zoom.us", "Zoom"),
        ("*.zoomgov.com", "Zoom"),
        ("*.netflix.com", "Netflix"),
        ("*.nflxvideo.net", "Netflix"),
        ("*.spotify.com", "Spotify"),
        ("*.scdn.co", "Spotify"),
        ("*.twitch.tv", "Twitch"),
        ("*.ttvnw.net", "Twitch"),

        // --- Steam / games ---
        ("*.steampowered.com", "Steam"),
        ("*.steamcontent.com", "Steam"),
        ("*.steamserver.net", "Steam"),
        ("*.steamstatic.com", "Steam"),
        ("*.epicgames.com", "Epic Games"),
        ("*.unrealengine.com", "Epic Games"),

        // --- Cloud / CDN ---
        ("*.cloudflare.com", "Cloudflare"),
        ("*.cloudflare.net", "Cloudflare"),
        ("*.cloudflareinsights.com", "Cloudflare"),
        ("*.amazonaws.com", "AWS"),
        ("*.cloudfront.net", "CloudFront"),
        ("*.fastly.net", "Fastly CDN"),
        ("*.fastlylb.net", "Fastly CDN"),
        ("*.akamaized.net", "Akamai CDN"),
        ("*.akamai.net", "Akamai"),
        ("*.akamaitechnologies.com", "Akamai"),
        ("*.edgesuite.net", "Akamai"),

        // --- Russian services ---
        ("*.yandex.net", "Yandex"),
        ("*.yandex.ru", "Yandex"),
        ("*.vk.com", "VK"),
        ("*.vkuser.net", "VK"),
        ("*.mail.ru", "Mail.ru"),
        ("*.mradx.net", "Mail.ru"),
        ("*.ok.ru", "Odnoklassniki"),

        // --- Common protocol-ish hostnames ---
        // time.windows.com и *.time.apple.com перенесены выше — до общих правил
        // *.windows.com и *.apple.com, которые их затеняли
        ("*.ntp.org", "NTP"),
    };

    public static string Classify(string hostname)
    {
        if (string.IsNullOrEmpty(hostname)) return string.Empty;
        var h = hostname.ToLowerInvariant();
        foreach (var (pattern, label) in Rules)
        {
            if (Match(pattern, h))
                return label;
        }
        return string.Empty;
    }

    private static bool Match(string pattern, string hostname)
    {
        if (pattern.StartsWith("*."))
        {
            var suffix = pattern.AsSpan(1);
            return hostname.EndsWith(suffix.ToString(), StringComparison.Ordinal)
                || hostname == suffix.Slice(1).ToString();
        }
        if (pattern.EndsWith(".*"))
        {
            var prefix = pattern.AsSpan(0, pattern.Length - 1).ToString();
            if (prefix.StartsWith("*."))
                prefix = prefix.Substring(2);
            return hostname.Contains("." + prefix) || hostname.StartsWith(prefix, StringComparison.Ordinal);
        }
        if (pattern.Contains('*'))
        {
            var pieces = pattern.Split('*');
            int idx = 0;
            for (int i = 0; i < pieces.Length; i++)
            {
                var p = pieces[i];
                if (p.Length == 0) continue;
                int found = hostname.IndexOf(p, idx, StringComparison.Ordinal);
                if (found < 0) return false;
                if (i == 0 && !pattern.StartsWith("*") && found != 0) return false;
                idx = found + p.Length;
            }
            return true;
        }
        return pattern == hostname;
    }
}
