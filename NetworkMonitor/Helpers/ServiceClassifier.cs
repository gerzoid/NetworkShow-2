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
        ("*.office.com", "Office365"),
        ("*.office.net", "Office365"),
        ("*.officeapps.live.com", "Office365"),
        ("*.office365.com", "Office365"),
        ("*.outlook.com", "Outlook"),
        ("*.outlook.office365.com", "Outlook"),
        ("*.outlook.office.com", "Outlook"),
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
        ("*.azure.com", "Azure"),
        ("*.azureedge.net", "Azure CDN"),
        ("*.azurefd.net", "Azure Front Door"),
        ("*.blob.core.windows.net", "Azure Blob"),
        ("*.queue.core.windows.net", "Azure Queue"),
        ("*.table.core.windows.net", "Azure Table"),
        ("*.file.core.windows.net", "Azure Files"),
        ("*.servicebus.windows.net", "Azure ServiceBus"),
        ("*.cognitiveservices.azure.com", "Azure AI"),
        ("*.openai.azure.com", "Azure OpenAI"),
        ("*.applicationinsights.azure.com", "AppInsights"),
        ("*.applicationinsights.io", "AppInsights"),
        ("dc.services.visualstudio.com", "AppInsights"),
        ("*.visualstudio.com", "VisualStudio"),
        ("*.vsassets.io", "VisualStudio"),
        ("*.visualstudio.microsoft.com", "VisualStudio"),
        ("*.windows.com", "Windows"),
        ("*.windows.net", "Windows"),
        ("*.live.com", "Live"),
        ("*.live.net", "Live"),
        ("*.microsoft.com", "Microsoft"),
        ("*.msn.com", "MSN"),

        // --- Code / Devtools ---
        ("*.github.com", "GitHub"),
        ("github.com", "GitHub"),
        ("api.github.com", "GitHub API"),
        ("*.githubusercontent.com", "GitHub"),
        ("*.githubassets.com", "GitHub"),
        ("*.githubcopilot.com", "Copilot"),
        ("*.copilot.github.com", "Copilot"),
        ("*.gitlab.com", "GitLab"),
        ("*.bitbucket.org", "Bitbucket"),
        ("*.npmjs.com", "npm"),
        ("*.npmjs.org", "npm"),
        ("registry.npmjs.org", "npm"),
        ("*.nuget.org", "NuGet"),
        ("*.docker.io", "Docker"),
        ("*.docker.com", "Docker"),
        ("hub.docker.com", "Docker Hub"),
        ("*.jetbrains.com", "JetBrains"),

        // --- Anthropic / OpenAI / AI ---
        ("*.anthropic.com", "Anthropic"),
        ("api.anthropic.com", "Anthropic API"),
        ("claude.ai", "Claude"),
        ("*.claude.ai", "Claude"),
        ("api.openai.com", "OpenAI"),
        ("*.openai.com", "OpenAI"),
        ("chat.openai.com", "ChatGPT"),

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
        ("*.apple.com", "Apple"),
        ("*.icloud.com", "iCloud"),
        ("*.itunes.apple.com", "iTunes"),
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
        ("*.ntp.org", "NTP"),
        ("time.windows.com", "NTP"),
        ("*.time.apple.com", "NTP"),
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
