using System.Windows;

namespace PasswordVault.App.Services;

/// <summary>
/// Switches the WPF <see cref="ThemeMode"/> between System, Light, and Dark Windows 11 Fluent themes.
/// </summary>
public sealed class WindowsThemeService : IThemeService
{
    public void ApplyTheme(AppThemeOption theme)
    {
        if (Application.Current is null)
        {
            return;
        }

        Application.Current.ThemeMode = theme switch
        {
            AppThemeOption.Light => ThemeMode.Light,
            AppThemeOption.Dark => ThemeMode.Dark,
            _ => ThemeMode.System
        };
    }
}
