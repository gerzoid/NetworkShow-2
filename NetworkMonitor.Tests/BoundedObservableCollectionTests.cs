using System.Collections.Generic;
using System.Collections.ObjectModel;
using NetworkMonitor.Helpers;
using Xunit;

namespace NetworkMonitor.Tests;

public class BoundedObservableCollectionTests
{
    [Fact]
    public void Add_BeyondLimit_TrimsOldest()
    {
        var col = new BoundedObservableCollection<int>(3);
        for (int i = 1; i <= 5; i++) col.Add(i);
        Assert.Equal(new[] { 3, 4, 5 }, col);
    }

    [Fact]
    public void Add_ViaBaseTypeReference_StillTrims()
    {
        // Регрессия: с `new Add` вызов через базовый тип обходил обрезку
        var col = new BoundedObservableCollection<int>(3);
        ICollection<int> asInterface = col;
        for (int i = 1; i <= 10; i++) asInterface.Add(i);
        Assert.Equal(3, col.Count);
        Assert.Equal(new[] { 8, 9, 10 }, col);
    }

    [Fact]
    public void Add_ViaObservableCollectionReference_StillTrims()
    {
        var col = new BoundedObservableCollection<int>(2);
        ObservableCollection<int> asBase = col;
        for (int i = 1; i <= 5; i++) asBase.Add(i);
        Assert.Equal(2, col.Count);
    }

    [Fact]
    public void Insert_AtZero_KeepsNewestItem()
    {
        var col = new BoundedObservableCollection<int>(3);
        for (int i = 1; i <= 3; i++) col.Add(i);
        col.Insert(0, 99);
        Assert.Equal(3, col.Count);
        Assert.Equal(99, col[0]); // вставленный элемент не должен быть обрезан
    }

    [Fact]
    public void AddBatch_TrimsToLimit()
    {
        var col = new BoundedObservableCollection<int>(4);
        col.AddBatch(new[] { 1, 2, 3, 4, 5, 6 });
        Assert.Equal(new[] { 3, 4, 5, 6 }, col);
    }
}
