using System.Collections.ObjectModel;

namespace NetworkMonitor.Helpers;

public sealed class BoundedObservableCollection<T> : ObservableCollection<T>
{
    public int Limit { get; set; }

    public BoundedObservableCollection(int limit) { Limit = limit; }

    protected override void InsertItem(int index, T item)
    {
        base.InsertItem(index, item);
        TrimOldest(keepIndex: index);
    }

    public void AddBatch(System.Collections.Generic.IEnumerable<T> items)
    {
        foreach (var i in items) Add(i);
    }

    private void TrimOldest(int keepIndex)
    {
        // Не удаляем только что вставленный элемент: если вставка была в начало,
        // обрезаем с противоположного конца.
        while (Count > Limit && Limit > 0)
        {
            if (keepIndex == 0) RemoveAt(Count - 1);
            else { RemoveAt(0); keepIndex--; }
        }
    }
}
