using System.Collections.ObjectModel;

namespace NetworkMonitor.Helpers;

public sealed class BoundedObservableCollection<T> : ObservableCollection<T>
{
    public int Limit { get; set; }

    public BoundedObservableCollection(int limit) { Limit = limit; }

    public new void Add(T item)
    {
        base.Add(item);
        TrimOldest();
    }

    public void AddBatch(System.Collections.Generic.IEnumerable<T> items)
    {
        foreach (var i in items) base.Add(i);
        TrimOldest();
    }

    private void TrimOldest()
    {
        while (Count > Limit) RemoveAt(0);
    }
}
