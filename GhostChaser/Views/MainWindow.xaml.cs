using GhostChaser.ViewModels;
using System.Windows;
using System.Windows.Controls;

namespace GhostChaser.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            // Bind password box to ViewModel
            PasswordBox.PasswordChanged += PasswordBox_PasswordChanged;
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel viewModel && sender is PasswordBox passwordBox)
            {
                viewModel.Password = passwordBox.SecurePassword;
            }
        }
    }
}
