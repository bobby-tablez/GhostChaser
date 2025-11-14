using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace GhostChaser.Converters
{
    public class StatusColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool isError)
            {
                return isError ?
                    new SolidColorBrush(Color.FromRgb(231, 76, 60)) : // Error red
                    new SolidColorBrush(Colors.White); // Normal white
            }
            return new SolidColorBrush(Colors.White);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
