using NetworkMonitor.Models;
using NetworkMonitor.Services;
using NetworkMonitor.ViewModels;
using Xunit;

namespace NetworkMonitor.Tests;

[Collection("Settings")]
public class IpAliasTests
{
    public IpAliasTests()
    {
        SettingsService.Persist = false;
        SettingsService.Current.IpAliases = new();
        IpAliasService.Load(null);
        IpAliasService.LanNameLookup = null;
    }

    [Fact]
    public void SetResolveRemove_AndPersistedInSettings()
    {
        IpAliasService.Set("8.8.8.8", "  Google DNS ");
        Assert.Equal("Google DNS", IpAliasService.Resolve("8.8.8.8"));
        Assert.Equal("Google DNS", SettingsService.Current.IpAliases["8.8.8.8"]);

        IpAliasService.Set("8.8.8.8", "");
        Assert.Equal(string.Empty, IpAliasService.Resolve("8.8.8.8"));
        Assert.Empty(SettingsService.Current.IpAliases);
    }

    [Fact]
    public void Load_RestoresSavedNames()
    {
        IpAliasService.Load(new Dictionary<string, string> { ["10.0.0.5"] = "Сервер", [" "] = "x" });
        Assert.Equal("Сервер", IpAliasService.Resolve("10.0.0.5"));
        Assert.Single(IpAliasService.All());
    }

    [Fact]
    public void LanName_UsedWhenNoExplicitAlias()
    {
        IpAliasService.LanNameLookup = ip => ip == "192.168.1.60" ? "Телевизор в зале" : null;
        Assert.Equal("Телевизор в зале", IpAliasService.Resolve("192.168.1.60"));
        IpAliasService.Set("192.168.1.60", "Мой ТВ");
        Assert.Equal("Мой ТВ", IpAliasService.Resolve("192.168.1.60")); // явное имя важнее
    }

    [Fact]
    public void NewAggregates_GetAliasAtCreation()
    {
        IpAliasService.Set("8.8.8.8", "Google DNS");
        var agg = new AggregationService();
        agg.Add(new PacketRecord
        {
            Protocol = "UDP", Direction = TrafficDirection.Outbound, SourceIp = "192.168.1.2", DestinationIp = "8.8.8.8",
            SourcePort = 5000, DestinationPort = 53, Size = 100, ProcessName = "x", Timestamp = DateTime.Now
        });
        Assert.Equal("Google DNS", agg.Connections.Single().Alias);
        Assert.Equal("Google DNS", agg.RemoteIps.Single().Alias);
    }

    [Fact]
    public void IpNamesViewModel_ListsAllNames_AndAddsValidated()
    {
        var status = new List<string>();
        IpNamesViewModel? vm = null;
        vm = new IpNamesViewModel(
            () => new List<(string, string, string)> { ("192.168.1.60", "ТВ", "AA-AA-AA-AA-AA-02") },
            (ip, name) => { IpAliasService.Set(ip, name); vm!.Reload(); },
            status.Add);
        IpAliasService.Set("1.1.1.1", "Cloudflare");
        vm.Reload();
        Assert.Equal(2, vm.Entries.Count);
        Assert.Contains(vm.Entries, e => e.Ip == "192.168.1.60" && !e.IsEditable);

        vm.NewIp = "не адрес"; vm.NewName = "x";
        vm.AddCommand.Execute(null);
        Assert.Equal(2, vm.Entries.Count); // отклонено

        vm.NewIp = "9.9.9.9"; vm.NewName = "Quad9";
        vm.AddCommand.Execute(null);
        Assert.Contains(vm.Entries, e => e.Ip == "9.9.9.9" && e.Name == "Quad9");

        vm.Selected = vm.Entries.First(e => e.Ip == "9.9.9.9");
        vm.DeleteSelectedCommand.Execute(null);
        Assert.DoesNotContain(vm.Entries, e => e.Ip == "9.9.9.9");
    }
}
