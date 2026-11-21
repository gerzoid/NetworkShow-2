using System;
using System.Globalization;
using System.Windows.Data;

namespace NetworkMonitor.Converters;

public sealed class ShareToggleTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? "Остановить мониторинг шар" : "Запустить мониторинг шар";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
