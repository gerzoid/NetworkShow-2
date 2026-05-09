using System;
using System.Globalization;
using System.Windows.Data;
using NetworkMonitor.Helpers;

namespace NetworkMonitor.Converters;

public sealed class BytesConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value switch
        {
            long l => ByteFormatter.Format(l),
            int i => ByteFormatter.Format(i),
            _ => value?.ToString() ?? string.Empty
        };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}
