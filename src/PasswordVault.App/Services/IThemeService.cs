namespace PasswordVault.App.Services;

/// <summary>
/// Supported Windows Fluent appearance modes.
/// </summary>
public enum AppThemeOption
{
    System,
    Light,
    Dark
}

/// <summary>
/// Applies runtime Windows Fluent themes to the WPF application.
/// </summary>
public interface IThemeService
{
    void ApplyTheme(AppThemeOption theme);
}
