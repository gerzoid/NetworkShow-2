using NetworkMonitor.Helpers;
using Xunit;

namespace NetworkMonitor.Tests;

public class ServiceClassifierTests
{
    [Theory]
    // Специфичные правила, которые раньше затенялись общими
    [InlineData("api.github.com", "GitHub API")]
    [InlineData("x.copilot.github.com", "Copilot")]
    [InlineData("chat.openai.com", "ChatGPT")]
    [InlineData("hub.docker.com", "Docker Hub")]
    [InlineData("registry.npmjs.org", "npm")]
    [InlineData("api.anthropic.com", "Anthropic API")]
    [InlineData("x.outlook.office.com", "Outlook")]
    [InlineData("x.outlook.office365.com", "Outlook")]
    [InlineData("x.openai.azure.com", "Azure OpenAI")]
    [InlineData("x.cognitiveservices.azure.com", "Azure AI")]
    [InlineData("x.applicationinsights.azure.com", "AppInsights")]
    [InlineData("time.windows.com", "NTP")]
    [InlineData("x.time.apple.com", "NTP")]
    [InlineData("x.itunes.apple.com", "iTunes")]
    // Общие правила по-прежнему работают
    [InlineData("github.com", "GitHub")]
    [InlineData("raw.githubusercontent.com", "GitHub")]
    [InlineData("api.openai.com", "OpenAI")]
    [InlineData("x.teams.microsoft.com", "Teams")]
    [InlineData("www.microsoft.com", "Microsoft")]
    [InlineData("claude.ai", "Claude")]
    [InlineData("www.apple.com", "Apple")]
    [InlineData("www.windows.com", "Windows")]
    [InlineData("cdn.discordapp.com", "Discord")]
    public void Classify_ReturnsExpectedLabel(string hostname, string expected)
    {
        Assert.Equal(expected, ServiceClassifier.Classify(hostname));
    }

    [Theory]
    [InlineData("")]
    [InlineData("example.com")]
    [InlineData("unknown-host.local")]
    public void Classify_UnknownHost_ReturnsEmpty(string hostname)
    {
        Assert.Equal(string.Empty, ServiceClassifier.Classify(hostname));
    }

    [Fact]
    public void Classify_IsCaseInsensitive()
    {
        Assert.Equal("GitHub API", ServiceClassifier.Classify("API.GITHUB.COM"));
    }
}
