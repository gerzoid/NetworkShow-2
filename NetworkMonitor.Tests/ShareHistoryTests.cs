using System.IO;
using NetworkMonitor.Models;
using NetworkMonitor.ViewModels;
using Xunit;

namespace NetworkMonitor.Tests;

public class ShareHistoryTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "ns-share-" + Guid.NewGuid().ToString("N") + ".csv");
    public void Dispose() { try { File.Delete(_path); } catch { } }

    [Fact]
    public void ReadCsvHistory_RestoresEvents_IncludingQuotedFields()
    {
        File.WriteAllText(_path,
            "timestamp,kind,source,client,client_port,user,share,path,access,result,via\r\n" +
            "2026-11-21T10:00:00.0000000+08:00,Session,Сессия,100.64.0.1,,DESKTOP\\gerz,Save,,Подключение,OK,\r\n" +
            "2026-11-21T10:00:05.0000000+08:00,FileAccess,Аудит,192.168.1.40,50111,user,Save,\"папка, с запятой\\file \"\"1\"\".zip\",\"Чтение, Запись\",ОТКАЗ,\r\n" +
            "битая строка\r\n");

        var list = ShareAccessViewModel.ReadCsvHistory(_path, 100);
        Assert.Equal(2, list.Count);
        Assert.Equal(ShareEventKind.Session, list[0].Kind);
        Assert.Equal("100.64.0.1", list[0].Client);
        Assert.False(list[0].Denied);
        Assert.Equal("папка, с запятой\\file \"1\".zip", list[1].Path);
        Assert.Equal("Чтение, Запись", list[1].Access);
        Assert.True(list[1].Denied);
    }

    [Fact]
    public void ReadCsvHistory_MissingFile_IsEmpty() =>
        Assert.Empty(ShareAccessViewModel.ReadCsvHistory(_path + ".nope", 10));
}
