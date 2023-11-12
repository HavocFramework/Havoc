#include <Util/ColorText.h>

QString HavocNamespace::Util::ColorText::Colors::Hex::Background    = "#282a36";
QString HavocNamespace::Util::ColorText::Colors::Hex::Foreground    = "#f8f8f2";
QString HavocNamespace::Util::ColorText::Colors::Hex::Comment       = "#6272a4";
QString HavocNamespace::Util::ColorText::Colors::Hex::CurrentLine   = "#44475a";

QString HavocNamespace::Util::ColorText::Colors::Hex::Cyan          = "#8be9fd";
QString HavocNamespace::Util::ColorText::Colors::Hex::Green         = "#50fa7b";
QString HavocNamespace::Util::ColorText::Colors::Hex::Orange        = "#ffb86c";
QString HavocNamespace::Util::ColorText::Colors::Hex::Pink          = "#ff79c6";
QString HavocNamespace::Util::ColorText::Colors::Hex::Purple        = "#bd93f9";
QString HavocNamespace::Util::ColorText::Colors::Hex::Red           = "#ff5555";
QString HavocNamespace::Util::ColorText::Colors::Hex::Yellow        = "#f1fa8c";

QString HavocNamespace::Util::ColorText::Colors::Hex::SessionCyan   = "#618bac";
QString HavocNamespace::Util::ColorText::Colors::Hex::SessionGreen  = "#1C5F11";
QString HavocNamespace::Util::ColorText::Colors::Hex::SessionOrange = "#ac7420";
QString HavocNamespace::Util::ColorText::Colors::Hex::SessionPink   = "#c33fb6";
QString HavocNamespace::Util::ColorText::Colors::Hex::SessionPurple = "#36365b";
QString HavocNamespace::Util::ColorText::Colors::Hex::SessionRed    = "#5b3d3e";
QString HavocNamespace::Util::ColorText::Colors::Hex::SessionYellow = "#a59220";

void HavocNamespace::Util::ColorText::SetDraculaDark()
{
    HavocNamespace::Util::ColorText::Colors::Hex::Background    = "#282a36";
    HavocNamespace::Util::ColorText::Colors::Hex::Foreground    = "#f8f8f2";
    HavocNamespace::Util::ColorText::Colors::Hex::Comment       = "#6272a4";
    HavocNamespace::Util::ColorText::Colors::Hex::CurrentLine   = "#44475a";

    HavocNamespace::Util::ColorText::Colors::Hex::Cyan          = "#8be9fd";
    HavocNamespace::Util::ColorText::Colors::Hex::Green         = "#50fa7b";
    HavocNamespace::Util::ColorText::Colors::Hex::Orange        = "#ffb86c";
    HavocNamespace::Util::ColorText::Colors::Hex::Pink          = "#ff79c6";
    HavocNamespace::Util::ColorText::Colors::Hex::Purple        = "#bd93f9";
    HavocNamespace::Util::ColorText::Colors::Hex::Red           = "#ff5555";
    HavocNamespace::Util::ColorText::Colors::Hex::Yellow        = "#f1fa8c";
}

void HavocNamespace::Util::ColorText::SetDraculaLight()
{
    // TODO: get white theme
}

QString HavocNamespace::Util::ColorText::Color(const QString& color, const QString &text)
{
    return "<span style=\"color: "+ color +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Background(const QString& text)
{
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Background +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Foreground(const QString& text) {
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Foreground +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Comment(const QString& text) {
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Comment +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Cyan(const QString& text) {
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Cyan +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Green(const QString& text) {
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Green +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Orange(const QString& text) {
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Orange +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Pink(const QString& text) {
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Pink +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Purple(const QString& text) {
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Purple +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Red(const QString& text) {
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Red +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Yellow(const QString& text) {
    return "<span style=\"color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Yellow +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::Bold(const QString& text) {
    return "<b>" + text.toHtmlEscaped() + "</b>";
}

QString HavocNamespace::Util::ColorText::Underline(const QString &text) {
    return "<span style=\"text-decoration:underline\">" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlineBackground(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Background +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlineForeground(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Foreground +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlineComment(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Comment +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlineCyan(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Cyan +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlineGreen(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Green +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlineOrange(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Orange +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlinePink(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Pink +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlinePurple(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Purple +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlineRed(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Red +";\" >" + text.toHtmlEscaped() + "</span>";
}

QString HavocNamespace::Util::ColorText::UnderlineYellow(const QString &text) {
    return "<span style=\"text-decoration:underline; color: "+ HavocNamespace::Util::ColorText::Colors::Hex::Yellow +";\" >" + text.toHtmlEscaped() + "</span>";
}
